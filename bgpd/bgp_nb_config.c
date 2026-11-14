// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Northbound configuration callbacks
 * Copyright (C) 2026 FRRouting
 */
#include <zebra.h>
#include "typesafe.h"

#ifdef GNU_LINUX
#include <linux/rtnetlink.h> //RT_TABLE_XXX
#endif

#include "northbound.h"
#include "northbound_cli.h"
#include "libfrr.h"
#include "defaults.h"
#include "vrf.h"
#include "prefix.h"
#include "lib_errors.h"
#include "routing_nb.h"
#include "zebra.h"
#include "asn.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_open.h"
#include "bgpd/bgp_nb.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_addpath.h"
#include "bgpd/bgp_open.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_conditional_adv.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_mpath.h"
#include "bgpd/bgp_updgrp.h"
#include "bgpd/bgp_bfd.h"
#include "bgpd/bgp_evpn.h"
#include "bgpd/bgp_evpn_private.h"
#include "bgpd/bgp_evpn_mh.h"
#include "bgpd/bgp_zebra.h"
#include "routemap.h"
#include "filter.h"
#include "bfd.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_community_alias.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_lcommunity.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_io.h"
#include "bgpd/bgp_updgrp.h"
#include "bgpd/bgp_nht.h"
#include "bgpd/bgp_damp.h"
#include "frrdistance.h"
#include "bgpd/bgp_srv6.h"
#include "bgpd/bgp_bmp_nb.h"
#include "srv6.h"
#include "bgpd/bgp_ls.h"
#include "bgpd/bgp_pbr.h"

/*
 * Candidate-YANG xpaths for daemon vs per-instance mutual exclusion checks.
 */
#define BGP_NB_INST_GR_ENABLED_XPATH                                                              \
	"/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/graceful-restart/enabled[.='true']"
#define BGP_NB_INST_GR_DISABLE_XPATH                                                              \
	"/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/graceful-restart/graceful-restart-disable[.='true']"
#define BGP_NB_INST_GSHUT_XPATH                                                                   \
	"/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/graceful-shutdown/enable[.='true']"
#define BGP_NB_DAEMON_GSHUT_XPATH "/frr-bgp:bgp-daemon/graceful-shutdown/enable[.='true']"

DEFINE_HOOK(bgp_snmp_init_stats, (struct bgp *bgp), (bgp));
DEFINE_HOOK(bgp_route_distinguisher_update, (struct bgp *bgp, afi_t afi, bool preconfig),
	    (bgp, afi, preconfig));
DEFINE_HOOK(bgp_snmp_update_last_changed, (struct bgp *bgp), (bgp));

/* Same instance identity bgp_nb_bgp_create() uses on APPLY. */
static void bgp_nb_instance_key(const struct lyd_node *bgp_dnode, enum bgp_instance_type *inst_type,
				const char **inst_name)
{
	const char *vrf_name = yang_dnode_get_string(bgp_dnode, "../vrf");

	if (strmatch(vrf_name, VRF_DEFAULT_NAME)) {
		*inst_name = NULL;
		*inst_type = BGP_INSTANCE_TYPE_DEFAULT;
		return;
	}

	*inst_name = vrf_name;
	if (yang_dnode_exists(bgp_dnode, "./global/instance-type-view") &&
	    yang_dnode_get_bool(bgp_dnode, "./global/instance-type-view"))
		*inst_type = BGP_INSTANCE_TYPE_VIEW;
	else
		*inst_type = BGP_INSTANCE_TYPE_VRF;
}

static bool bgp_nb_cpp_is_bgp(const struct lyd_node *cpp)
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

static bool bgp_nb_instance_same(enum bgp_instance_type a, const char *aname, enum bgp_instance_type b,
				 const char *bname)
{
	if (a != b)
		return false;
	if (!aname || !bname)
		return !aname && !bname;
	return strmatch(aname, bname);
}

/*
 * The list key is (type, name, vrf), but the instance is looked up by the
 * vrf leaf. Two entries that resolve to the same instance would share one
 * struct bgp and bgp_delete() either of them out from under the other.
 */
static int bgp_nb_bgp_validate_unique(struct nb_cb_create_args *args)
{
	const struct lyd_node *cpp, *sib, *other;
	enum bgp_instance_type mine_type, other_type;
	const char *mine_name, *other_name;
	const char *vrf;

	cpp = yang_dnode_get_parent(args->dnode, "control-plane-protocol");
	if (!cpp || !lyd_parent(cpp))
		return NB_OK;

	bgp_nb_instance_key(args->dnode, &mine_type, &mine_name);
	LY_LIST_FOR (lyd_child(lyd_parent(cpp)), sib) {
		if (sib == cpp || !bgp_nb_cpp_is_bgp(sib))
			continue;
		other = yang_dnode_get(sib, "frr-bgp:bgp");
		if (!other)
			other = yang_dnode_get(sib, "bgp");
		if (!other)
			continue;
		bgp_nb_instance_key(other, &other_type, &other_name);
		if (!bgp_nb_instance_same(mine_type, mine_name, other_type, other_name))
			continue;

		vrf = yang_dnode_get_string(args->dnode, "../vrf");
		snprintfrr(args->errmsg, args->errmsg_len,
			   "BGP instance for vrf %s is already configured", vrf);
		return NB_ERR_VALIDATION;
	}
	return NB_OK;
}

/*
 * bgp_get_vty() enables neighbor-change logging for the datacenter profile.
 * The YANG default stays false, and a leaf whose value equals that default
 * is not a configuration diff, so an implicit false must not clear the flag.
 * An explicit value is not marked LYD_DEFAULT once the candidate is validated.
 */
static void bgp_nb_apply_explicit_log_neighbor_changes(struct bgp *bgp, const struct lyd_node *bgp_dnode)
{
	const struct lyd_node *leaf;

	if (!bgp || !yang_dnode_exists(bgp_dnode, "./global/global-neighbor-config/log-neighbor-changes"))
		return;

	leaf = yang_dnode_get(bgp_dnode, "./global/global-neighbor-config/log-neighbor-changes");
	if (!leaf || (leaf->flags & LYD_DEFAULT))
		return;
	if (yang_dnode_get_bool(leaf, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_LOG_NEIGHBOR_CHANGES);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_LOG_NEIGHBOR_CHANGES);
}

/*
 * XPath: .../frr-bgp:bgp
 */
int bgp_nb_bgp_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp = NULL;
	const char *name;
	enum bgp_instance_type inst_type;
	enum asnotation_mode asnotation = ASNOTATION_UNDEFINED;
	const char *notation;
	as_t as;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_nb_bgp_validate_unique(args);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		as = yang_dnode_get_uint32(args->dnode, "./global/local-as");
		bgp_nb_instance_key(args->dnode, &inst_type, &name);

		if (yang_dnode_exists(args->dnode, "./global/as-notation")) {
			notation = yang_dnode_get_string(args->dnode, "./global/as-notation");
			if (strmatch(notation, "dot+"))
				asnotation = ASNOTATION_DOTPLUS;
			else if (strmatch(notation, "dot"))
				asnotation = ASNOTATION_DOT;
			else
				asnotation = ASNOTATION_PLAIN;
		}

		/*
		 * Match classic router_bgp: look up with force_config so an
		 * AUTO instance created by L3VNI (same VRF name) is reclaimed
		 * instead of skipped. bgp_get_vty() filters AUTO and would
		 * create a second struct bgp — config (RD/Type-5) then lands
		 * on the YANG instance while L3VNI stays on the AUTO one
		 * (memory leak + missing EVPN prefixes).
		 */
		ret = bgp_lookup_by_as_name_type(&bgp, &as, NULL, asnotation, name, inst_type,
						 true);
		if (!(bgp && ret == BGP_INSTANCE_EXISTS)) {
			ret = bgp_get_vty(&bgp, &as, name, inst_type, NULL, asnotation);
			if (ret != BGP_SUCCESS && ret != BGP_CREATED && ret != BGP_INSTANCE_EXISTS)
				return NB_ERR_RESOURCE;
		}

		if (inst_type == BGP_INSTANCE_TYPE_VRF || IS_BGP_INSTANCE_HIDDEN(bgp)) {
			struct vrf *vrf;

			bgp_vpn_leak_export(bgp);
			UNSET_FLAG(bgp->vrf_flags, BGP_VRF_AUTO);
			UNSET_FLAG(bgp->flags, BGP_FLAG_INSTANCE_HIDDEN);
			UNSET_FLAG(bgp->flags, BGP_FLAG_DELETE_IN_PROGRESS);

			/* Ensure the claimed instance owns the VRF link. */
			if (name) {
				vrf = vrf_lookup_by_name(name);
				if (vrf && (bgp->vrf_id != vrf->vrf_id || vrf->info != (void *)bgp))
					bgp_vrf_link(bgp, vrf);
			}
		}

		nb_running_set_entry(args->dnode, bgp);
		bgp_vpn_leak_export(bgp);

		/*
		 * bgp_create() seeds default_af IPv4 unicast. Under XFRR
		 * batching, the router-bgp seed CREATE of default-afi-safi
		 * ipv4-unicast and "no bgp default ipv4-unicast" DESTROY
		 * cancel in the candidate, so the destroy callback never
		 * runs and peers stay IPv4-activated (e.g. BGP-LS fabric
		 * tests leak EBGP prefixes as LS NLRIs). Clear the C
		 * default here; child default-afi-safi create callbacks
		 * re-apply only what remains in the committed tree.
		 */
		bgp->default_af[AFI_IP][SAFI_UNICAST] = false;

		/*
		 * Inverse race: L3VNI may already be live when the VRF BGP
		 * instance is created/claimed from YANG. Re-apply ip-vrf
		 * leaves now (no-op if they are not in running yet; child
		 * APPLY / later L3VNI reapply covers the other order).
		 */
		if (bgp->l3vni)
			bgp_nb_evpn_vrf_yang_reapply(bgp);
		bgp_nb_apply_explicit_log_neighbor_changes(bgp, args->dnode);
		break;
	}

	return NB_OK;
}

int bgp_nb_bgp_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const char *vrf_name;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, false);
	if (bgp) {
		nb_running_unset_entry(args->dnode);
	} else {
		vrf_name = yang_dnode_get_string(args->dnode, "../vrf");
		if (strmatch(vrf_name, VRF_DEFAULT_NAME))
			bgp = bgp_get_default();
		else
			bgp = bgp_lookup_by_name(vrf_name);
		if (!bgp)
			return NB_OK;
	}

	bgp_delete(bgp);
	return NB_OK;
}

int bgp_nb_routing_destroy(struct nb_cb_destroy_args *args)
{
	struct lyd_node *bgp_dnode;
	struct nb_cb_destroy_args destroy_args;
	const char *type;

	type = yang_dnode_get_string(args->dnode, "type");
	if (!type || !strmatch(type, "frr-bgp:bgp"))
		return NB_OK;

	bgp_dnode = yang_dnode_get(args->dnode, "frr-bgp:bgp");
	if (!bgp_dnode)
		return NB_OK;

	memset(&destroy_args, 0, sizeof(destroy_args));
	destroy_args.dnode = bgp_dnode;
	destroy_args.event = args->event;
	return bgp_nb_bgp_destroy(&destroy_args);
}

/*
 * YANG stores ASNs as plain uint32. Format show output using the instance
 * as-notation so ASDOT configs round-trip and frr-reload does not churn
 * remote-as / local-as (which drops AF activation on reset).
 */
static enum asnotation_mode bgp_nb_cli_dnode_asnotation(const struct lyd_node *dnode)
{
	const struct lyd_node *bgp;
	enum asnotation_mode asnotation = ASNOTATION_PLAIN;

	bgp = yang_dnode_get_parent(dnode, "bgp");
	if (!bgp)
		return asnotation;

	if (yang_dnode_exists(bgp, "./global/as-notation")) {
		const char *notation = yang_dnode_get_string(bgp, "./global/as-notation");

		if (strmatch(notation, "dot+"))
			asnotation = ASNOTATION_DOTPLUS;
		else if (strmatch(notation, "dot"))
			asnotation = ASNOTATION_DOT;
	}
	return asnotation;
}

/*
 * Update peer->as_pretty from the configured uint32 ASN and instance
 * as-notation without resetting the session (ASDOT vs plain churn).
 */
static void bgp_nb_peer_update_as_pretty(struct peer *peer, const struct lyd_node *dnode, as_t as)
{
	enum asnotation_mode asnotation = bgp_nb_cli_dnode_asnotation(dnode);
	char buf[32];

	snprintfrr(buf, sizeof(buf), ASN_FORMAT(asnotation), &as);
	if (peer->as_pretty && strmatch(peer->as_pretty, buf))
		return;
	if (peer->as_pretty)
		XFREE(MTYPE_BGP_NAME, peer->as_pretty);
	peer->as_pretty = XSTRDUP(MTYPE_BGP_NAME, buf);
}

void bgp_nb_cli_show_router_bgp(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const struct lyd_node *cpp;
	const char *vrf_name;
	const char *name;
	as_t as;
	bool is_view = false;
	enum asnotation_mode asnotation = ASNOTATION_PLAIN;

	cpp = yang_dnode_get_parent(dnode, "control-plane-protocol");
	vrf_name = yang_dnode_get_string(cpp, "vrf");
	name = yang_dnode_get_string(cpp, "name");
	as = yang_dnode_get_uint32(dnode, "./global/local-as");

	if (yang_dnode_exists(dnode, "./global/instance-type-view"))
		is_view = yang_dnode_get_bool(dnode, "./global/instance-type-view");

	if (yang_dnode_exists(dnode, "./global/as-notation")) {
		const char *notation = yang_dnode_get_string(dnode, "./global/as-notation");

		if (strmatch(notation, "dot+"))
			asnotation = ASNOTATION_DOTPLUS;
		else if (strmatch(notation, "dot"))
			asnotation = ASNOTATION_DOT;
	}

	vty_out(vty, "!\n");
	vty_out(vty, "router bgp ");
	vty_out(vty, ASN_FORMAT(asnotation), &as);
	if (is_view)
		vty_out(vty, " view %s", name);
	else if (!strmatch(vrf_name, VRF_DEFAULT_NAME))
		vty_out(vty, " vrf %s", vrf_name);
	/*
	 * Do not emit "as-notation ..." here. ASDOT is already reflected in
	 * the ASN display; printing the keyword makes config deltas generate
	 * "no router bgp X as-notation ..." which the YANG CLI does not
	 * accept (classic also omits the keyword when notation was inferred).
	 */
	vty_out(vty, "\n");

	/*
	 * "no bgp log-neighbor-changes" equals the YANG default, so the leaf
	 * writer is skipped on a normal save. Emit it from the operational
	 * flag when that differs from the active defaults profile.
	 */
	if (!show_defaults) {
		const struct lyd_node *leaf = NULL;
		struct bgp *bgp;
		bool enabled;
		bool profile_on = (frr_default_chosen() == FRR_DEFAULT_DATACENTER);

		if (yang_dnode_exists(dnode, "./global/global-neighbor-config/log-neighbor-changes"))
			leaf = yang_dnode_get(dnode, "./global/global-neighbor-config/log-neighbor-changes");
		if (!leaf || yang_dnode_is_default(leaf, NULL)) {
			bgp = nb_running_get_entry(dnode, NULL, false);
			if (bgp) {
				enabled = !!CHECK_FLAG(bgp->flags, BGP_FLAG_LOG_NEIGHBOR_CHANGES);
				if (enabled != profile_on)
					vty_out(vty, " %sbgp log-neighbor-changes\n", enabled ? "" : "no ");
			}
		}
	}
}

void bgp_nb_cli_show_router_bgp_end(struct vty *vty, const struct lyd_node *dnode)
{
	vty_out(vty, "exit\n");
}

/*
 * Dump a neighbor / peer-group / unnumbered entry without walking
 * afi-safis. Peer AF knobs are emitted inside address-family blocks by
 * bgp_nb_cli_show_global_afi_safi_end().
 */
static void bgp_nb_cli_show_dnode_skip_afi_safis(struct vty *vty, const struct lyd_node *dnode)
{
	struct nb_node *nb_node;
	const struct lyd_node *child;

	if (yang_dnode_is_default_recursive(dnode))
		return;

	nb_node = dnode->schema->priv;
	if (nb_node && nb_node->cbs.cli_show)
		(*nb_node->cbs.cli_show)(vty, dnode, false);

	if (!(dnode->schema->nodetype & (LYS_LEAF | LYS_LEAFLIST | LYS_ANYDATA))) {
		LY_LIST_FOR (lyd_child(dnode), child) {
			if (strmatch(child->schema->name, "afi-safis"))
				continue;
			nb_cli_show_dnode_cmds(vty, child, false);
		}
	}

	if (nb_node && nb_node->cbs.cli_show_end)
		(*nb_node->cbs.cli_show_end)(vty, dnode);
}

static void bgp_nb_cli_show_container_entries_skip_af(struct vty *vty,
						      const struct lyd_node *container)
{
	const struct lyd_node *child;

	if (!container)
		return;

	LY_LIST_FOR (lyd_child(container), child)
		bgp_nb_cli_show_dnode_skip_afi_safis(vty, child);
}

/*
 * Build absolute xpath for a BGP instance's frr-bgp:bgp container.
 * Keys match router_bgp_yang: default uses default/default; VRF and view
 * instances use name=vrf=bgp->name.
 */
const char *bgp_nb_instance_xpath(const struct bgp *bgp, char *buf, size_t buflen)
{
	const char *name = VRF_DEFAULT_NAME;
	const char *vrf = VRF_DEFAULT_NAME;

	if (bgp->name) {
		name = bgp->name;
		vrf = bgp->name;
	}

	snprintfrr(buf, buflen,
		   "/frr-routing:routing/control-plane-protocols/control-plane-protocol[type='frr-bgp:bgp'][name='%s'][vrf='%s']/frr-bgp:bgp",
		   name, vrf);
	return buf;
}

/*
 * Locate the running-config frr-bgp:bgp dnode for a BGP instance by walking
 * control-plane-protocol list keys (name/vrf). Avoids identityref predicates
 * in xpath lookups that silently fail (type-5 / RD reapply no-op).
 */
static const struct lyd_node *bgp_nb_find_instance_dnode(const struct bgp *bgp)
{
	const struct lyd_node *root, *cpps, *cpp, *bgp_dnode;
	const char *want_name = VRF_DEFAULT_NAME;
	const char *want_vrf = VRF_DEFAULT_NAME;
	const char *name, *vrf, *type;

	if (!bgp || !running_config || !running_config->dnode)
		return NULL;

	if (bgp->name) {
		want_name = bgp->name;
		want_vrf = bgp->name;
	}

	root = running_config->dnode;
	cpps = yang_dnode_get(root, "/frr-routing:routing/control-plane-protocols");
	if (!cpps)
		return NULL;

	LY_LIST_FOR (lyd_child(cpps), cpp) {
		if (!strmatch(cpp->schema->name, "control-plane-protocol"))
			continue;
		if (!yang_dnode_exists(cpp, "./type") || !yang_dnode_exists(cpp, "./name") ||
		    !yang_dnode_exists(cpp, "./vrf"))
			continue;
		type = yang_dnode_get_string(cpp, "./type");
		/*
		 * Identityref string form varies by libyang (frr-bgp:bgp,
		 * bgp, …). Accept any value whose final identity name is bgp.
		 */
		if (!type)
			continue;
		{
			const char *id = strrchr(type, ':');

			id = id ? id + 1 : type;
			if (!strmatch(id, "bgp"))
				continue;
		}
		name = yang_dnode_get_string(cpp, "./name");
		vrf = yang_dnode_get_string(cpp, "./vrf");
		if (!strmatch(name, want_name) || !strmatch(vrf, want_vrf))
			continue;
		bgp_dnode = yang_dnode_get(cpp, "frr-bgp:bgp");
		if (bgp_dnode)
			return bgp_dnode;
	}

	return NULL;
}

/*
 * Resolve struct bgp * for a dnode under frr-bgp:bgp by walking up to the
 * control-plane-protocol name/vrf keys. Prefer this over nb_running_get_entry
 * alone for EVPN ip-vrf leaves — parent-chain entry lookup has bound the
 * wrong (default) instance and made RD / type-5 APPLY a silent no-op.
 */
static struct bgp *bgp_nb_dnode_lookup_bgp(const struct lyd_node *dnode)
{
	const struct lyd_node *cpp;
	const char *name, *vrf;
	struct bgp *bgp;

	cpp = yang_dnode_get_parent(dnode, "control-plane-protocol");
	if (cpp && yang_dnode_exists(cpp, "name") && yang_dnode_exists(cpp, "vrf")) {
		name = yang_dnode_get_string(cpp, "name");
		vrf = yang_dnode_get_string(cpp, "vrf");
		if (strmatch(vrf, VRF_DEFAULT_NAME))
			bgp = bgp_get_default();
		else
			bgp = bgp_lookup_by_name(name);
		if (bgp)
			return bgp;
	}

	return nb_running_get_entry(dnode, NULL, false);
}

/*
 * Orchestrated per-instance CLI dump. Naive nb_cli_show_dnode_cmds() on
 * frr-bgp:bgp is wrong: peer AF config must appear inside address-family
 * frames, and bgp default shutdown / bgp shutdown must follow peers.
 */
void bgp_nb_cli_show_instance(struct vty *vty, const struct lyd_node *bgp)
{
	const struct lyd_node *global, *child, *afs, *vnc;
	static const char *const defer[] = {
		"afi-safis", "default-shutdown", "shutdown", "shutdown-message", NULL,
	};
	unsigned int i;
	bool skip;

	bgp_nb_cli_show_router_bgp(vty, bgp, false);

	global = yang_dnode_get(bgp, "global");
	if (global) {
		struct bgp *bgp_inst;

		LY_LIST_FOR (lyd_child(global), child) {
			skip = false;
			for (i = 0; defer[i]; i++) {
				if (strmatch(child->schema->name, defer[i])) {
					skip = true;
					break;
				}
			}
			if (skip)
				continue;
			nb_cli_show_dnode_cmds(vty, child, false);
		}

		/*
		 * ipv4-unicast is the implicit default (seeded in YANG, omitted
		 * from show). When cleared, emit the classic negative so
		 * write-config / reload keeps default_af false.
		 */
		bgp_inst = nb_running_get_entry(bgp, NULL, false);
		if (bgp_inst && !bgp_inst->default_af[AFI_IP][SAFI_UNICAST])
			vty_out(vty, " no bgp default ipv4-unicast\n");
	}

	bgp_nb_cli_show_container_entries_skip_af(vty, yang_dnode_get(bgp, "peer-groups"));
	bgp_nb_cli_show_container_entries_skip_af(vty, yang_dnode_get(bgp, "neighbors"));

	/*
	 * bgp default shutdown / bgp shutdown must dump after peers so a
	 * reload does not shut every peer (see #2286).
	 */
	if (global) {
		child = yang_dnode_get(global, "default-shutdown");
		if (child)
			nb_cli_show_dnode_cmds(vty, child, false);
		child = yang_dnode_get(global, "shutdown");
		if (child)
			nb_cli_show_dnode_cmds(vty, child, false);
		child = yang_dnode_get(global, "shutdown-message");
		if (child)
			nb_cli_show_dnode_cmds(vty, child, false);
	}

	afs = yang_dnode_get(bgp, "global/afi-safis");
	if (afs) {
		LY_LIST_FOR (lyd_child(afs), child) {
			if (!strmatch(child->schema->name, "afi-safi"))
				continue;
			nb_cli_show_dnode_cmds(vty, child, false);
		}
	}

	vnc = yang_dnode_get(bgp, "frr-bgp-vnc:vnc");
	if (vnc)
		nb_cli_show_dnode_cmds(vty, vnc, false);

	bgp_nb_cli_show_router_bgp_end(vty, bgp);
	vty_out(vty, "!\n");
}

void bgp_nb_cli_show_instance_bgp(struct vty *vty, struct bgp *bgp)
{
	const struct lyd_node *dnode;

	dnode = bgp_nb_find_instance_dnode(bgp);
	if (!dnode)
		return;

	bgp_nb_cli_show_instance(vty, dnode);
}

/*
 * XPath: .../global/local-as
 */
int bgp_nb_local_as_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	as_t new_as, old_as;
	struct peer *peer;
	struct listnode *node;

	switch (args->event) {
	case NB_EV_VALIDATE:
		/*
		 * Reject changing the instance AS to a value already used as a
		 * peer local-as override (classic peer_local_as_set constraint).
		 */
		bgp = nb_running_get_entry(args->dnode, NULL, false);
		if (!bgp)
			return NB_OK;
		new_as = yang_dnode_get_uint32(args->dnode, NULL);
		for (ALL_LIST_ELEMENTS_RO(bgp->peer, node, peer)) {
			if (CHECK_FLAG(peer->flags, PEER_FLAG_LOCAL_AS) &&
			    peer->change_local_as == new_as) {
				snprintfrr(args->errmsg, args->errmsg_len,
					   "Cannot have local-as same as BGP AS number");
				return NB_ERR_VALIDATION;
			}
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	new_as = yang_dnode_get_uint32(args->dnode, NULL);
	old_as = bgp->as;
	if (old_as == new_as)
		return NB_OK;

	bgp->as = new_as;
	for (ALL_LIST_ELEMENTS_RO(bgp->peer, node, peer)) {
		if (peer->local_as == old_as)
			peer->local_as = new_as;
	}

	return NB_OK;
}

/*
 * XPath: .../global/router-id
 */
int bgp_nb_router_id_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct in_addr router_id;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (inet_pton(AF_INET, yang_dnode_get_string(args->dnode, NULL), &router_id) != 1)
		return NB_ERR_VALIDATION;
	bgp_router_id_static_set(bgp, router_id);
	return NB_OK;
}

int bgp_nb_router_id_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	struct in_addr router_id = {};

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp_router_id_static_set(bgp, router_id);
	return NB_OK;
}

void bgp_nb_cli_show_router_id(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, " bgp router-id %s\n", yang_dnode_get_string(dnode, NULL));
}

int bgp_nb_instance_type_view_modify(struct nb_cb_modify_args *args)
{
	/* Applied at create time via bgp_nb_bgp_create; nothing further. */
	return NB_OK;
}

int bgp_nb_as_notation_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *notation;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	notation = yang_dnode_get_string(args->dnode, NULL);
	if (strmatch(notation, "dot+"))
		bgp->asnotation = ASNOTATION_DOTPLUS;
	else if (strmatch(notation, "dot"))
		bgp->asnotation = ASNOTATION_DOT;
	else
		bgp->asnotation = ASNOTATION_PLAIN;
	return NB_OK;
}

int bgp_nb_log_neighbor_changes_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_LOG_NEIGHBOR_CHANGES);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_LOG_NEIGHBOR_CHANGES);
	return NB_OK;
}

void bgp_nb_cli_show_log_neighbor_changes(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults)
{
	bool enabled = yang_dnode_get_bool(dnode, NULL);
	bool profile_on = (frr_default_chosen() == FRR_DEFAULT_DATACENTER);

	/*
	 * Match classic config write: keep the line only when it differs
	 * from the active defaults profile, so "no bgp log-neighbor-changes"
	 * survives a save under datacenter.
	 */
	if (!show_defaults && enabled == profile_on)
		return;
	vty_out(vty, " %sbgp log-neighbor-changes\n", enabled ? "" : "no ");
}

int bgp_nb_ebgp_requires_policy_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_EBGP_REQUIRES_POLICY);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_EBGP_REQUIRES_POLICY);
	return NB_OK;
}

void bgp_nb_cli_show_ebgp_requires_policy(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults)
{
	bool enabled = yang_dnode_get_bool(dnode, NULL);

	if (enabled)
		vty_out(vty, " bgp ebgp-requires-policy\n");
	else
		vty_out(vty, " no bgp ebgp-requires-policy\n");
}

int bgp_nb_import_check_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL)) {
		if (CHECK_FLAG(bgp->flags, BGP_FLAG_IMPORT_CHECK))
			return NB_OK;
		SET_FLAG(bgp->flags, BGP_FLAG_IMPORT_CHECK);
	} else {
		if (!CHECK_FLAG(bgp->flags, BGP_FLAG_IMPORT_CHECK))
			return NB_OK;
		UNSET_FLAG(bgp->flags, BGP_FLAG_IMPORT_CHECK);
	}
	bgp_static_redo_import_check(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_import_check(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	bool enabled = yang_dnode_get_bool(dnode, NULL);

	if (enabled)
		vty_out(vty, " bgp network import-check\n");
	else
		vty_out(vty, " no bgp network import-check\n");
}

int bgp_nb_cluster_id_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct in_addr cluster;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (!inet_aton(yang_dnode_get_string(args->dnode, NULL), &cluster)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "Malformed bgp cluster identifier");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	inet_aton(yang_dnode_get_string(args->dnode, NULL), &cluster);
	bgp_cluster_id_set(bgp, &cluster);
	bgp_clear_all_soft_out(bgp);
	return NB_OK;
}

int bgp_nb_cluster_id_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp_cluster_id_unset(bgp);
	bgp_clear_all_soft_out(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_cluster_id(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, " bgp cluster-id %s\n", yang_dnode_get_string(dnode, NULL));
}

int bgp_nb_no_client_reflect_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_NO_CLIENT_TO_CLIENT);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_NO_CLIENT_TO_CLIENT);
	bgp_clear_all_soft_out(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_no_client_reflect(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no bgp client-to-client reflection\n");
	else if (show_defaults)
		vty_out(vty, " bgp client-to-client reflection\n");
}

int bgp_nb_always_compare_med_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_ALWAYS_COMPARE_MED);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_ALWAYS_COMPARE_MED);
	bgp_recalculate_all_bestpaths(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_always_compare_med(struct vty *vty, const struct lyd_node *dnode,
					bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp always-compare-med\n");
	else if (show_defaults)
		vty_out(vty, " no bgp always-compare-med\n");
}

int bgp_nb_deterministic_med_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct peer *peer;
	struct listnode *node, *nnode;
	afi_t afi;
	safi_t safi;
	bool enable;

	enable = yang_dnode_get_bool(args->dnode, NULL);

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (enable)
			return NB_OK;
		bgp = nb_running_get_entry(args->dnode, NULL, false);
		if (!bgp)
			return NB_OK;
		if (!CHECK_FLAG(bgp->flags, BGP_FLAG_DETERMINISTIC_MED))
			return NB_OK;
		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
			FOREACH_AFI_SAFI (afi, safi) {
				if (bgp_addpath_dmed_required(peer->addpath_type[afi][safi])) {
					snprintfrr(args->errmsg, args->errmsg_len,
						   "bgp deterministic-med cannot be disabled while addpath-tx-bestpath-per-AS is in use");
					return NB_ERR_VALIDATION;
				}
			}
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (enable) {
		if (!CHECK_FLAG(bgp->flags, BGP_FLAG_DETERMINISTIC_MED)) {
			SET_FLAG(bgp->flags, BGP_FLAG_DETERMINISTIC_MED);
			bgp_recalculate_all_bestpaths(bgp);
		}
	} else if (CHECK_FLAG(bgp->flags, BGP_FLAG_DETERMINISTIC_MED)) {
		UNSET_FLAG(bgp->flags, BGP_FLAG_DETERMINISTIC_MED);
		bgp_recalculate_all_bestpaths(bgp);
	}
	return NB_OK;
}

void bgp_nb_cli_show_deterministic_med(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp deterministic-med\n");
	else if (show_defaults)
		vty_out(vty, " no bgp deterministic-med\n");
}

int bgp_nb_local_pref_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp_default_local_preference_set(bgp, yang_dnode_get_uint32(args->dnode, NULL));
	bgp_clear_all_soft_in(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_local_pref(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	uint32_t pref = yang_dnode_get_uint32(dnode, NULL);

	if (pref != 100 || show_defaults)
		vty_out(vty, " bgp default local-preference %u\n", pref);
}

int bgp_nb_fast_external_failover_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	bool enabled;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	/* YANG true => feature enabled => clear NO_FAST flag */
	enabled = yang_dnode_get_bool(args->dnode, NULL);
	if (enabled)
		UNSET_FLAG(bgp->flags, BGP_FLAG_NO_FAST_EXT_FAILOVER);
	else
		SET_FLAG(bgp->flags, BGP_FLAG_NO_FAST_EXT_FAILOVER);
	return NB_OK;
}

void bgp_nb_cli_show_fast_external_failover(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no bgp fast-external-failover\n");
	else if (show_defaults)
		vty_out(vty, " bgp fast-external-failover\n");
}

int bgp_nb_suppress_duplicates_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_SUPPRESS_DUPLICATES);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_SUPPRESS_DUPLICATES);
	return NB_OK;
}

void bgp_nb_cli_show_suppress_duplicates(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL)) {
		if (show_defaults)
			vty_out(vty, " bgp suppress-duplicates\n");
	} else
		vty_out(vty, " no bgp suppress-duplicates\n");
}

int bgp_nb_graceful_shutdown_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	bool enable;

	enable = yang_dnode_get_bool(args->dnode, NULL);

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (yang_dnode_exists(args->dnode, BGP_NB_DAEMON_GSHUT_XPATH)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "per-vrf graceful-shutdown not permitted with global graceful-shutdown");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (enable) {
		if (!CHECK_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_SHUTDOWN)) {
			SET_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_SHUTDOWN);
			bgp_initiate_graceful_shut_unshut(bgp);
		}
	} else if (CHECK_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_SHUTDOWN)) {
		UNSET_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_SHUTDOWN);
		bgp_initiate_graceful_shut_unshut(bgp);
	}
	return NB_OK;
}

void bgp_nb_cli_show_graceful_shutdown(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp graceful-shutdown\n");
	else if (show_defaults)
		vty_out(vty, " no bgp graceful-shutdown\n");
}

int bgp_nb_reject_as_sets_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct listnode *node, *nnode;
	struct peer *peer;
	bool reject;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	reject = yang_dnode_get_bool(args->dnode, NULL);
	if (bgp->reject_as_sets == reject)
		return NB_OK;

	bgp->reject_as_sets = reject;
	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
		peer_set_last_reset(peer, PEER_DOWN_AS_SETS_REJECT);
		peer_notify_config_change(peer->connection);
	}
	return NB_OK;
}

void bgp_nb_cli_show_reject_as_sets(struct vty *vty, const struct lyd_node *dnode,
				    bool show_defaults)
{
	/* Default is true; only emit "no" when disabled. */
	if (yang_dnode_get_bool(dnode, NULL)) {
		if (show_defaults)
			vty_out(vty, " bgp reject-as-sets\n");
	} else
		vty_out(vty, " no bgp reject-as-sets\n");
}

int bgp_nb_enforce_first_as_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct listnode *node;
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	bool enable;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	enable = yang_dnode_get_bool(args->dnode, NULL);
	if (enable) {
		if (CHECK_FLAG(bgp->flags, BGP_FLAG_ENFORCE_FIRST_AS))
			return NB_OK;
		SET_FLAG(bgp->flags, BGP_FLAG_ENFORCE_FIRST_AS);
	} else {
		if (!CHECK_FLAG(bgp->flags, BGP_FLAG_ENFORCE_FIRST_AS))
			return NB_OK;
		UNSET_FLAG(bgp->flags, BGP_FLAG_ENFORCE_FIRST_AS);
	}

	for (ALL_LIST_ELEMENTS_RO(bgp->peer, node, peer)) {
		FOREACH_AFI_SAFI (afi, safi)
			peer_on_policy_change(peer, afi, safi, 0);
	}
	return NB_OK;
}

void bgp_nb_cli_show_enforce_first_as(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp enforce-first-as\n");
	else
		vty_out(vty, " no bgp enforce-first-as\n");
}

int bgp_nb_connected_route_check_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	/* YANG true => disable connected NH check */
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_DISABLE_NH_CONNECTED_CHK);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_DISABLE_NH_CONNECTED_CHK);
	bgp_clear_all_soft_in(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_connected_route_check(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp disable-ebgp-connected-route-check\n");
	else if (show_defaults)
		vty_out(vty, " no bgp disable-ebgp-connected-route-check\n");
}

int bgp_nb_allow_outbound_policy_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	bool enable;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	enable = yang_dnode_get_bool(args->dnode, NULL);
	if (enable) {
		if (CHECK_FLAG(bgp->flags, BGP_FLAG_RR_ALLOW_OUTBOUND_POLICY))
			return NB_OK;
		SET_FLAG(bgp->flags, BGP_FLAG_RR_ALLOW_OUTBOUND_POLICY);
	} else {
		if (!CHECK_FLAG(bgp->flags, BGP_FLAG_RR_ALLOW_OUTBOUND_POLICY))
			return NB_OK;
		UNSET_FLAG(bgp->flags, BGP_FLAG_RR_ALLOW_OUTBOUND_POLICY);
	}
	update_group_announce_rrclients(bgp);
	bgp_clear_all_soft_out(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_allow_outbound_policy(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp route-reflector allow-outbound-policy\n");
	else if (show_defaults)
		vty_out(vty, " no bgp route-reflector allow-outbound-policy\n");
}

int bgp_nb_hard_admin_reset_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_HARD_ADMIN_RESET);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_HARD_ADMIN_RESET);
	return NB_OK;
}

void bgp_nb_cli_show_hard_admin_reset(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp hard-administrative-reset\n");
	else
		vty_out(vty, " no bgp hard-administrative-reset\n");
}

int bgp_nb_show_hostname_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_SHOW_HOSTNAME);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_SHOW_HOSTNAME);
	return NB_OK;
}

void bgp_nb_cli_show_show_hostname(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp default show-hostname\n");
	else if (show_defaults)
		vty_out(vty, " no bgp default show-hostname\n");
}

int bgp_nb_show_nexthop_hostname_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_SHOW_NEXTHOP_HOSTNAME);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_SHOW_NEXTHOP_HOSTNAME);
	return NB_OK;
}

void bgp_nb_cli_show_show_nexthop_hostname(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp default show-nexthop-hostname\n");
	else if (show_defaults)
		vty_out(vty, " no bgp default show-nexthop-hostname\n");
}

int bgp_nb_external_compare_router_id_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_COMPARE_ROUTER_ID);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_COMPARE_ROUTER_ID);
	bgp_recalculate_all_bestpaths(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_external_compare_router_id(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp bestpath compare-routerid\n");
	else if (show_defaults)
		vty_out(vty, " no bgp bestpath compare-routerid\n");
}

int bgp_nb_ignore_as_path_length_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_ASPATH_IGNORE);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_ASPATH_IGNORE);
	bgp_recalculate_all_bestpaths(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_ignore_as_path_length(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp bestpath as-path ignore\n");
	else if (show_defaults)
		vty_out(vty, " no bgp bestpath as-path ignore\n");
}

int bgp_nb_compare_aigp_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_COMPARE_AIGP);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_COMPARE_AIGP);
	bgp_recalculate_all_bestpaths(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_compare_aigp(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp bestpath aigp\n");
	else if (show_defaults)
		vty_out(vty, " no bgp bestpath aigp\n");
}

int bgp_nb_use_imported_attributes_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	bool enable;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	enable = yang_dnode_get_bool(args->dnode, NULL);
	if (enable == !!CHECK_FLAG(bgp->flags, BGP_FLAG_BESTPATH_USE_IMPORTED_ATTRS))
		return NB_OK;
	if (enable)
		SET_FLAG(bgp->flags, BGP_FLAG_BESTPATH_USE_IMPORTED_ATTRS);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_BESTPATH_USE_IMPORTED_ATTRS);
	bgp_recalculate_all_bestpaths(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_use_imported_attributes(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp bestpath use-imported-attributes\n");
	else if (show_defaults)
		vty_out(vty, " no bgp bestpath use-imported-attributes\n");
}

int bgp_nb_aspath_confed_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_ASPATH_CONFED);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_ASPATH_CONFED);
	bgp_recalculate_all_bestpaths(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_aspath_confed(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp bestpath as-path confed\n");
	else if (show_defaults)
		vty_out(vty, " no bgp bestpath as-path confed\n");
}

int bgp_nb_allow_multiple_as_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_ASPATH_MULTIPATH_RELAX);
	else {
		UNSET_FLAG(bgp->flags, BGP_FLAG_ASPATH_MULTIPATH_RELAX);
		UNSET_FLAG(bgp->flags, BGP_FLAG_MULTIPATH_RELAX_AS_SET);
	}
	bgp_recalculate_all_bestpaths(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_allow_multiple_as(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults)
{
	const struct lyd_node *parent = yang_dnode_get_parent(dnode, "route-selection-options");
	bool relax = yang_dnode_get_bool(dnode, NULL);

	/*
	 * multi-path-as-set defaults to false and is skipped by nb_cli_show,
	 * so "multipath-relax" with no as-set is printed here. When as-set is
	 * explicit, its callback prints the combined line.
	 */
	if (!relax) {
		if (show_defaults)
			vty_out(vty, " no bgp bestpath as-path multipath-relax\n");
		return;
	}
	if (parent && yang_dnode_exists(parent, "multi-path-as-set") &&
	    !yang_dnode_is_default(parent, "multi-path-as-set"))
		return;
	vty_out(vty, " bgp bestpath as-path multipath-relax\n");
}

int bgp_nb_multi_path_as_set_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_MULTIPATH_RELAX_AS_SET);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_MULTIPATH_RELAX_AS_SET);
	bgp_recalculate_all_bestpaths(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_multi_path_as_set(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults)
{
	const struct lyd_node *parent = yang_dnode_get_parent(dnode, "route-selection-options");
	bool relax;
	bool as_set;

	/* Default false is printed by allow-multiple-as, if at all. */
	if (yang_dnode_is_default(dnode, NULL))
		return;
	if (!parent)
		return;
	relax = yang_dnode_get_bool(parent, "allow-multiple-as");
	as_set = yang_dnode_get_bool(dnode, NULL);

	if (!relax)
		return;
	if (as_set)
		vty_out(vty, " bgp bestpath as-path multipath-relax as-set\n");
	else
		vty_out(vty, " bgp bestpath as-path multipath-relax\n");
}

int bgp_nb_peer_type_multipath_relax_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_PEERTYPE_MULTIPATH_RELAX);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_PEERTYPE_MULTIPATH_RELAX);
	bgp_recalculate_all_bestpaths(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_peer_type_multipath_relax(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp bestpath peer-type multipath-relax\n");
	else if (show_defaults)
		vty_out(vty, " no bgp bestpath peer-type multipath-relax\n");
}

int bgp_nb_confed_med_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_MED_CONFED);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_MED_CONFED);
	bgp_recalculate_all_bestpaths(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_confed_med(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const struct lyd_node *parent = yang_dnode_get_parent(dnode, "route-selection-options");

	if (!yang_dnode_get_bool(dnode, NULL))
		return;
	/*
	 * missing-as-worst-med prints the combined line when it is set.
	 * While that leaf is still the default, nb_cli_show skips it, so
	 * "bgp bestpath med confed" has to be printed from here.
	 */
	if (parent && yang_dnode_exists(parent, "missing-as-worst-med") &&
	    !yang_dnode_is_default(parent, "missing-as-worst-med"))
		return;
	vty_out(vty, " bgp bestpath med confed\n");
}

int bgp_nb_missing_as_worst_med_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_MED_MISSING_AS_WORST);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_MED_MISSING_AS_WORST);
	bgp_recalculate_all_bestpaths(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_missing_as_worst_med(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults)
{
	const struct lyd_node *parent = yang_dnode_get_parent(dnode, "route-selection-options");
	bool confed = false;
	bool missing;

	/* Default false must not reprint a confed-only line. */
	if (yang_dnode_is_default(dnode, NULL))
		return;
	if (!parent)
		return;
	missing = yang_dnode_get_bool(dnode, NULL);
	if (yang_dnode_exists(parent, "confed-med"))
		confed = yang_dnode_get_bool(parent, "confed-med");

	if (confed && missing)
		vty_out(vty, " bgp bestpath med confed missing-as-worst\n");
	else if (missing)
		vty_out(vty, " bgp bestpath med missing-as-worst\n");
}

int bgp_nb_bandwidth_handling_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *val;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	val = yang_dnode_get_string(args->dnode, NULL);
	if (strmatch(val, "ignore"))
		bgp->lb_handling = BGP_LINK_BW_IGNORE_BW;
	else if (strmatch(val, "skip-missing"))
		bgp->lb_handling = BGP_LINK_BW_SKIP_MISSING;
	else if (strmatch(val, "default-weight-for-missing"))
		bgp->lb_handling = BGP_LINK_BW_DEFWT_4_MISSING;
	else
		bgp->lb_handling = BGP_LINK_BW_ECMP;

	FOREACH_AFI_SAFI (afi, safi) {
		if (!bgp_fibupd_safi(safi))
			continue;
		bgp_zebra_announce_table(bgp, afi, safi);
	}
	return NB_OK;
}

void bgp_nb_cli_show_bandwidth_handling(struct vty *vty, const struct lyd_node *dnode,
					bool show_defaults)
{
	const char *val = yang_dnode_get_string(dnode, NULL);

	if (strmatch(val, "ecmp")) {
		if (show_defaults)
			vty_out(vty, " no bgp bestpath bandwidth\n");
		return;
	}
	vty_out(vty, " bgp bestpath bandwidth %s\n", val);
}

static void bgp_nb_apply_global_timers(struct bgp *bgp, const struct lyd_node *dnode)
{
	const struct lyd_node *timers;
	uint32_t keepalive;
	uint32_t holdtime;
	uint32_t connect_retry = DFLT_BGP_CONNECT_RETRY;

	timers = yang_dnode_get_parent(dnode, "global-config-timers");
	keepalive = yang_dnode_get_uint16(timers, "keepalive");
	holdtime = yang_dnode_get_uint16(timers, "hold-time");
	if (yang_dnode_exists(timers, "connect-retry-interval"))
		connect_retry = yang_dnode_get_uint16(timers, "connect-retry-interval");
	bgp_timers_set(NULL, bgp, keepalive, holdtime, connect_retry, BGP_DEFAULT_DELAYOPEN);
}

int bgp_nb_keepalive_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp_nb_apply_global_timers(bgp, args->dnode);
	return NB_OK;
}

int bgp_nb_hold_time_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE: {
		uint16_t holdtime = yang_dnode_get_uint16(args->dnode, NULL);

		if (holdtime < 3 && holdtime != 0) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "hold time value must be either 0 or greater than 3");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp_nb_apply_global_timers(bgp, args->dnode);
	return NB_OK;
}

void bgp_nb_cli_show_keepalive(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const struct lyd_node *timers = yang_dnode_get_parent(dnode, "global-config-timers");
	uint16_t keepalive = yang_dnode_get_uint16(dnode, NULL);
	uint16_t holdtime = yang_dnode_get_uint16(timers, "hold-time");

	if (keepalive != DFLT_BGP_KEEPALIVE || holdtime != DFLT_BGP_HOLDTIME || show_defaults)
		vty_out(vty, " timers bgp %u %u\n", keepalive, holdtime);
}

void bgp_nb_cli_show_holdtime(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const struct lyd_node *timers = yang_dnode_get_parent(dnode, "global-config-timers");
	const struct lyd_node *ka;
	uint16_t keepalive, holdtime;

	/*
	 * Keepalive owns this line when nb_cli_show will visit it. A default
	 * keepalive is skipped, which dropped "timers bgp 60 <hold>".
	 */
	ka = timers ? yang_dnode_get(timers, "keepalive") : NULL;
	if (ka && (show_defaults || !yang_dnode_is_default(ka, NULL)))
		return;

	keepalive = ka ? yang_dnode_get_uint16(ka, NULL) : DFLT_BGP_KEEPALIVE;
	holdtime = yang_dnode_get_uint16(dnode, NULL);
	if (keepalive != DFLT_BGP_KEEPALIVE || holdtime != DFLT_BGP_HOLDTIME || show_defaults)
		vty_out(vty, " timers bgp %u %u\n", keepalive, holdtime);
}

int bgp_nb_minimum_holdtime_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp->default_min_holdtime = yang_dnode_get_uint16(args->dnode, NULL);
	return NB_OK;
}

int bgp_nb_minimum_holdtime_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp->default_min_holdtime = 0;
	return NB_OK;
}

void bgp_nb_cli_show_minimum_holdtime(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults)
{
	vty_out(vty, " bgp minimum-holdtime %u\n", yang_dnode_get_uint16(dnode, NULL));
}

int bgp_nb_confederation_identifier_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp_confederation_id_set(bgp, yang_dnode_get_uint32(args->dnode, NULL),
				 yang_dnode_get_string(args->dnode, NULL));
	return NB_OK;
}

int bgp_nb_confederation_identifier_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp_confederation_id_unset(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_confederation_identifier(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults)
{
	struct bgp *bgp = nb_running_get_entry(dnode, NULL, false);

	/*
	 * Prefer confed_id_pretty so ASDOT input like "1.0" round-trips;
	 * YANG leaf is asplain uint32 and would always show "65536".
	 */
	if (bgp && bgp->confed_id_pretty)
		vty_out(vty, " bgp confederation identifier %s\n", bgp->confed_id_pretty);
	else
		vty_out(vty, " bgp confederation identifier %s\n",
			yang_dnode_get_string(dnode, NULL));
}

int bgp_nb_confederation_member_as_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp_confederation_peers_add(bgp, yang_dnode_get_uint32(args->dnode, NULL),
				    yang_dnode_get_string(args->dnode, NULL));
	return NB_OK;
}

int bgp_nb_confederation_member_as_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp_confederation_peers_remove(bgp, yang_dnode_get_uint32(args->dnode, NULL));
	return NB_OK;
}

void bgp_nb_cli_show_confederation_member_as(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults)
{
	vty_out(vty, " bgp confederation peers %s\n", yang_dnode_get_string(dnode, NULL));
}

int bgp_nb_enable_med_admin_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		bgp->v_maxmed_admin = 1;
	else {
		bgp->v_maxmed_admin = BGP_MAXMED_ADMIN_UNCONFIGURED;
		bgp->maxmed_admin_value = BGP_MAXMED_VALUE_DEFAULT;
	}
	bgp_maxmed_update(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_enable_med_admin(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults)
{
	const struct lyd_node *med = yang_dnode_get_parent(dnode, "med-config");
	uint32_t value;

	if (!yang_dnode_get_bool(dnode, NULL))
		return;

	/*
	 * This leaf is false by default, so the callback runs whenever
	 * administrative max-med is on. max-med-admin itself is skipped when
	 * it stays at the default, which dropped the bare command.
	 */
	value = (med && yang_dnode_exists(med, "max-med-admin"))
		? yang_dnode_get_uint32(med, "max-med-admin")
		: BGP_MAXMED_VALUE_DEFAULT;
	if (value == BGP_MAXMED_VALUE_DEFAULT)
		vty_out(vty, " bgp max-med administrative\n");
	else
		vty_out(vty, " bgp max-med administrative %u\n", value);
}

int bgp_nb_max_med_admin_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const struct lyd_node *med;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	med = yang_dnode_get_parent(args->dnode, "med-config");
	if (!yang_dnode_get_bool(med, "enable-med-admin"))
		return NB_OK;

	bgp->maxmed_admin_value = yang_dnode_get_uint32(args->dnode, NULL);
	bgp_maxmed_update(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_max_med_admin(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults)
{
	/*
	 * Printed by bgp_nb_cli_show_enable_med_admin. enable-med-admin is not a
	 * default whenever the command is configured, including when this value
	 * stays at BGP_MAXMED_VALUE_DEFAULT.
	 */
}

int bgp_nb_max_med_onstartup_time_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const struct lyd_node *med;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	med = yang_dnode_get_parent(args->dnode, "med-config");
	bgp->v_maxmed_onstartup = yang_dnode_get_uint32(args->dnode, NULL);
	if (yang_dnode_exists(med, "max-med-onstart-up-value"))
		bgp->maxmed_onstartup_value = yang_dnode_get_uint32(med,
								    "max-med-onstart-up-value");
	else
		bgp->maxmed_onstartup_value = BGP_MAXMED_VALUE_DEFAULT;
	bgp_maxmed_update(bgp);
	return NB_OK;
}

int bgp_nb_max_med_onstartup_time_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (event_is_scheduled(bgp->t_maxmed_onstartup)) {
		event_cancel(&bgp->t_maxmed_onstartup);
		bgp->maxmed_onstartup_over = 1;
	}
	bgp->v_maxmed_onstartup = BGP_MAXMED_ONSTARTUP_UNCONFIGURED;
	bgp->maxmed_onstartup_value = BGP_MAXMED_VALUE_DEFAULT;
	bgp_maxmed_update(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_max_med_onstartup_time(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults)
{
	const struct lyd_node *med = yang_dnode_get_parent(dnode, "med-config");
	uint32_t time = yang_dnode_get_uint32(dnode, NULL);
	uint32_t value = BGP_MAXMED_VALUE_DEFAULT;

	if (yang_dnode_exists(med, "max-med-onstart-up-value"))
		value = yang_dnode_get_uint32(med, "max-med-onstart-up-value");

	if (value == BGP_MAXMED_VALUE_DEFAULT)
		vty_out(vty, " bgp max-med on-startup %u\n", time);
	else
		vty_out(vty, " bgp max-med on-startup %u %u\n", time, value);
}

int bgp_nb_max_med_onstartup_value_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const struct lyd_node *med;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	med = yang_dnode_get_parent(args->dnode, "med-config");
	if (!yang_dnode_exists(med, "max-med-onstart-up-time"))
		return NB_OK;

	bgp->maxmed_onstartup_value = yang_dnode_get_uint32(args->dnode, NULL);
	bgp_maxmed_update(bgp);
	return NB_OK;
}

int bgp_nb_update_delay_time_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const struct lyd_node *timers;
	uint16_t delay;
	uint16_t wait;

	delay = yang_dnode_get_uint16(args->dnode, NULL);
	timers = yang_dnode_get_parent(args->dnode, "global-config-timers");
	if (yang_dnode_exists(timers, "establish-wait-time"))
		wait = yang_dnode_get_uint16(timers, "establish-wait-time");
	else
		wait = delay;

	switch (args->event) {
	case NB_EV_VALIDATE:
		/*
		 * Mutual exclusion vs daemon-wide update-delay from candidate
		 * YANG only — never bm->v_update_delay operational state.
		 * delay vs establish-wait is constrained by YANG must.
		 */
		if (yang_dnode_exists(args->dnode, "/frr-bgp:bgp-daemon/update-delay-time")) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "per-vrf update-delay not permitted with global update-delay");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp->v_update_delay = delay;
	bgp->v_establish_wait = wait;
	return NB_OK;
}

int bgp_nb_update_delay_time_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (yang_dnode_exists(args->dnode, "/frr-bgp:bgp-daemon/update-delay-time")) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "cannot remove per-vrf update-delay while global update-delay is set");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp->v_update_delay = BGP_UPDATE_DELAY_DEFAULT;
	bgp->v_establish_wait = BGP_UPDATE_DELAY_DEFAULT;
	return NB_OK;
}

void bgp_nb_cli_show_update_delay_time(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults)
{
	const struct lyd_node *timers = yang_dnode_get_parent(dnode, "global-config-timers");
	uint16_t delay = yang_dnode_get_uint16(dnode, NULL);
	uint16_t wait = delay;

	if (yang_dnode_exists(timers, "establish-wait-time"))
		wait = yang_dnode_get_uint16(timers, "establish-wait-time");

	if (wait != delay)
		vty_out(vty, " update-delay %u %u\n", delay, wait);
	else
		vty_out(vty, " update-delay %u\n", delay);
}

int bgp_nb_rmap_delay_time_modify(struct nb_cb_modify_args *args)
{
	uint16_t timer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	timer = yang_dnode_get_uint16(args->dnode, NULL);
	bm->rmap_update_timer = timer;

	/*
	 * Disabling the delay timer while one is armed: cancel and run the
	 * update immediately (matches classic CLI).
	 */
	if (!timer && event_is_scheduled(bm->t_rmap_update)) {
		event_cancel(&bm->t_rmap_update);
		event_execute(bm->master, bgp_route_map_update_timer, NULL, 0, NULL);
	}
	return NB_OK;
}

int bgp_nb_rmap_delay_time_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bm->rmap_update_timer = RMAP_DEFAULT_UPDATE_TIMER;
	return NB_OK;
}

void bgp_nb_cli_show_rmap_delay_time(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults)
{
	uint16_t timer = yang_dnode_get_uint16(dnode, NULL);

	if (timer != RMAP_DEFAULT_UPDATE_TIMER || show_defaults)
		vty_out(vty, " bgp route-map delay-timer %u\n", timer);
}

int bgp_nb_establish_wait_time_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const struct lyd_node *timers;
	uint16_t delay;
	uint16_t wait;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	timers = yang_dnode_get_parent(args->dnode, "global-config-timers");
	if (!yang_dnode_exists(timers, "update-delay-time"))
		return NB_OK;

	delay = yang_dnode_get_uint16(timers, "update-delay-time");
	wait = yang_dnode_get_uint16(args->dnode, NULL);
	bgp->v_update_delay = delay;
	bgp->v_establish_wait = wait;
	return NB_OK;
}

int bgp_nb_establish_wait_time_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const struct lyd_node *timers;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	timers = yang_dnode_get_parent(args->dnode, "global-config-timers");
	if (yang_dnode_exists(timers, "update-delay-time"))
		bgp->v_establish_wait = yang_dnode_get_uint16(timers, "update-delay-time");
	else
		bgp->v_establish_wait = BGP_UPDATE_DELAY_DEFAULT;
	return NB_OK;
}

int bgp_nb_advertisement_delay_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp->v_advertisement_delay = yang_dnode_get_uint16(args->dnode, NULL);
	return NB_OK;
}

int bgp_nb_advertisement_delay_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp->v_advertisement_delay = BGP_ADVERTISEMENT_DELAY_DEFAULT;
	if (bgp->advertisement_delay_started && !bgp->advertisement_delay_over) {
		event_cancel(&bgp->t_advertisement_delay);
		bgp->advertisement_delay_started = 0;
		bgp->advertisement_delay_over = 0;
		if (!bgp_update_delay_active(bgp) && !bgp->main_zebra_update_hold) {
			bgp->main_peers_update_hold = 0;
			bgp_start_routeadv(bgp);
		}
	} else {
		event_cancel(&bgp->t_advertisement_delay);
		bgp->advertisement_delay_started = 0;
		bgp->advertisement_delay_over = 0;
	}
	return NB_OK;
}

void bgp_nb_cli_show_advertisement_delay(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults)
{
	vty_out(vty, " advertisement-delay %u\n", yang_dnode_get_uint16(dnode, NULL));
}

int bgp_nb_conditional_advertisement_timer_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp_conditional_adv_period_set(bgp, yang_dnode_get_uint16(args->dnode, NULL));
	return NB_OK;
}

int bgp_nb_conditional_advertisement_timer_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	struct listnode *node, *nnode;
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (bgp->condition_check_period == DEFAULT_CONDITIONAL_ROUTES_POLL_TIME)
		return NB_OK;

	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer))
		UNSET_FLAG(peer->sflags, PEER_STATUS_COND_ADV_PENDING);

	bgp_conditional_adv_period_set(bgp, DEFAULT_CONDITIONAL_ROUTES_POLL_TIME);
	return NB_OK;
}

void bgp_nb_cli_show_conditional_advertisement_timer(struct vty *vty, const struct lyd_node *dnode,
						     bool show_defaults)
{
	uint16_t period = yang_dnode_get_uint16(dnode, NULL);

	if (period != DEFAULT_CONDITIONAL_ROUTES_POLL_TIME || show_defaults)
		vty_out(vty, " bgp conditional-advertisement timer %u\n", period);
}

int bgp_nb_default_originate_timer_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp->rmap_def_originate_eval_timer = yang_dnode_get_uint16(args->dnode, NULL);
	event_cancel(&bgp->t_rmap_def_originate_eval);
	return NB_OK;
}

int bgp_nb_default_originate_timer_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp->rmap_def_originate_eval_timer = 0;
	event_cancel(&bgp->t_rmap_def_originate_eval);
	return NB_OK;
}

void bgp_nb_cli_show_default_originate_timer(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults)
{
	uint16_t timer = yang_dnode_get_uint16(dnode, NULL);

	if (timer && timer != RMAP_DEFAULT_ORIGINATE_EVAL_TIMER)
		vty_out(vty, " bgp default-originate timer %u\n", timer);
	else if (show_defaults && timer)
		vty_out(vty, " bgp default-originate timer %u\n", timer);
}


int bgp_nb_dynamic_neighbors_limit_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp_listen_limit_set(bgp, yang_dnode_get_uint32(args->dnode, NULL));
	return NB_OK;
}

int bgp_nb_dynamic_neighbors_limit_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp_listen_limit_unset(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_dynamic_neighbors_limit(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults)
{
	uint32_t limit = yang_dnode_get_uint32(dnode, NULL);

	if (limit != BGP_DYNAMIC_NEIGHBORS_LIMIT_DEFAULT || show_defaults)
		vty_out(vty, " bgp listen limit %u\n", limit);
}

static int bgp_nb_parse_default_afi_safi(const char *afi_safi, afi_t *afi, safi_t *safi,
					 char *errmsg, size_t errmsg_len)
{
	char buf[64];
	char *tok = NULL;
	char *afi_str;
	char *safi_str;

	strlcpy(buf, afi_safi, sizeof(buf));
	afi_str = strtok_r(buf, "-", &tok);
	safi_str = strtok_r(NULL, "-", &tok);
	if (!afi_str || !safi_str) {
		snprintfrr(errmsg, errmsg_len, "Invalid AFI/SAFI %s", afi_safi);
		return NB_ERR_VALIDATION;
	}

	*afi = bgp_vty_afi_from_str(afi_str);
	if (*afi == AFI_MAX) {
		snprintfrr(errmsg, errmsg_len, "Invalid AFI in %s", afi_safi);
		return NB_ERR_VALIDATION;
	}

	if (strmatch(safi_str, "labeled"))
		*safi = bgp_vty_safi_from_str("labeled-unicast");
	else
		*safi = bgp_vty_safi_from_str(safi_str);

	if (*safi == SAFI_MAX) {
		snprintfrr(errmsg, errmsg_len, "Invalid SAFI in %s", afi_safi);
		return NB_ERR_VALIDATION;
	}
	return NB_OK;
}

int bgp_nb_default_afi_safi_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	int ret;

	ret = bgp_nb_parse_default_afi_safi(yang_dnode_get_string(args->dnode, NULL), &afi, &safi,
					    args->errmsg, args->errmsg_len);
	if (ret != NB_OK)
		return ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
		bgp = nb_running_get_entry(args->dnode, NULL, false);
		if (!bgp)
			return NB_OK;
		if ((safi == SAFI_LABELED_UNICAST && bgp->default_af[afi][SAFI_UNICAST]) ||
		    (safi == SAFI_UNICAST && bgp->default_af[afi][SAFI_LABELED_UNICAST])) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "Cannot activate both unicast and labeled-unicast by default");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp->default_af[afi][safi] = true;
	return NB_OK;
}

int bgp_nb_default_afi_safi_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	int ret;

	ret = bgp_nb_parse_default_afi_safi(yang_dnode_get_string(args->dnode, NULL), &afi, &safi,
					    args->errmsg, args->errmsg_len);
	if (ret != NB_OK)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp->default_af[afi][safi] = false;
	return NB_OK;
}

void bgp_nb_cli_show_default_afi_safi(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults)
{
	const char *afi_safi = yang_dnode_get_string(dnode, NULL);

	/*
	 * ipv4-unicast is seeded as the implicit C default on new instances.
	 * Omit from show running unless showing defaults (classic behavior).
	 */
	if (!show_defaults && strmatch(afi_safi, "ipv4-unicast"))
		return;

	vty_out(vty, " bgp default %s\n", afi_safi);
}

int bgp_nb_gr_stale_routes_time_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp->stalepath_time = yang_dnode_get_uint16(args->dnode, NULL);
	return NB_OK;
}

void bgp_nb_cli_show_gr_stale_routes_time(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults)
{
	uint16_t val = yang_dnode_get_uint16(dnode, NULL);

	if (val != BGP_DEFAULT_STALEPATH_TIME || show_defaults)
		vty_out(vty, " bgp graceful-restart stalepath-time %u\n", val);
}

static void bgp_nb_gr_restart_time_peers(struct bgp *bgp, bool unset)
{
	struct listnode *node, *nnode;
	struct peer *peer;

	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
		if (!CHECK_FLAG(peer->cap, PEER_CAP_DYNAMIC_RCV) ||
		    !CHECK_FLAG(peer->cap, PEER_CAP_DYNAMIC_ADV))
			bgp_update_graceful_restart_capability(peer);
		else
			bgp_capability_send(peer->connection, AFI_IP, SAFI_UNICAST,
					    CAPABILITY_CODE_RESTART,
					    unset ? CAPABILITY_ACTION_UNSET
						  : CAPABILITY_ACTION_SET);
	}
}

int bgp_nb_gr_restart_time_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp->restart_time = yang_dnode_get_uint16(args->dnode, NULL);
	bgp_nb_gr_restart_time_peers(bgp, false);
	return NB_OK;
}

void bgp_nb_cli_show_gr_restart_time(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults)
{
	uint16_t val = yang_dnode_get_uint16(dnode, NULL);

	if (val != BGP_DEFAULT_RESTART_TIME || show_defaults)
		vty_out(vty, " bgp graceful-restart restart-time %u\n", val);
}

int bgp_nb_gr_select_defer_time_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	uint16_t defer_time;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	defer_time = yang_dnode_get_uint16(args->dnode, NULL);
	bgp->select_defer_time = defer_time;
	if (defer_time == 0)
		SET_FLAG(bgp->flags, BGP_FLAG_SELECT_DEFER_DISABLE);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_SELECT_DEFER_DISABLE);
	return NB_OK;
}

void bgp_nb_cli_show_gr_select_defer_time(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults)
{
	uint16_t val = yang_dnode_get_uint16(dnode, NULL);

	if (val != BGP_DEFAULT_SELECT_DEFERRAL_TIME || show_defaults)
		vty_out(vty, " bgp graceful-restart select-defer-time %u\n", val);
}

int bgp_nb_gr_rib_stale_time_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp->rib_stale_time = yang_dnode_get_uint16(args->dnode, NULL);
	bgp_zebra_stale_timer_update(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_gr_rib_stale_time(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults)
{
	uint16_t val = yang_dnode_get_uint16(dnode, NULL);

	if (val != BGP_DEFAULT_RIB_STALE_TIME || show_defaults)
		vty_out(vty, " bgp graceful-restart rib-stale-time %u\n", val);
}

int bgp_nb_gr_preserve_fw_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_GR_PRESERVE_FWD);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_GR_PRESERVE_FWD);
	return NB_OK;
}

void bgp_nb_cli_show_gr_preserve_fw(struct vty *vty, const struct lyd_node *dnode,
				    bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp graceful-restart preserve-fw-state\n");
	else if (show_defaults)
		vty_out(vty, " no bgp graceful-restart preserve-fw-state\n");
}

int bgp_nb_gr_notification_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct listnode *node, *nnode;
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_NOTIFICATION);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_NOTIFICATION);

	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer))
		bgp_capability_send(peer->connection, AFI_IP, SAFI_UNICAST,
				    CAPABILITY_CODE_RESTART, CAPABILITY_ACTION_SET);
	return NB_OK;
}

int bgp_nb_gr_notification_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	struct listnode *node, *nnode;
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	UNSET_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_NOTIFICATION);
	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer))
		bgp_capability_send(peer->connection, AFI_IP, SAFI_UNICAST,
				    CAPABILITY_CODE_RESTART, CAPABILITY_ACTION_SET);
	return NB_OK;
}

void bgp_nb_cli_show_gr_notification(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp graceful-restart notification\n");
	else
		vty_out(vty, " no bgp graceful-restart notification\n");
}

int bgp_nb_gr_disable_eor_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_GR_DISABLE_EOR);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_GR_DISABLE_EOR);
	return NB_OK;
}

void bgp_nb_cli_show_gr_disable_eor(struct vty *vty, const struct lyd_node *dnode,
				    bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp graceful-restart disable-eor\n");
	else if (show_defaults)
		vty_out(vty, " no bgp graceful-restart disable-eor\n");
}

int bgp_nb_gr_llgr_stale_time_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct listnode *node, *nnode;
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp->llgr_stale_time = yang_dnode_get_uint32(args->dnode, NULL);
	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer))
		bgp_capability_send(peer->connection, AFI_IP, SAFI_UNICAST, CAPABILITY_CODE_LLGR,
				    CAPABILITY_ACTION_SET);
	return NB_OK;
}

void bgp_nb_cli_show_gr_llgr_stale_time(struct vty *vty, const struct lyd_node *dnode,
					bool show_defaults)
{
	uint32_t val = yang_dnode_get_uint32(dnode, NULL);

	if (val != BGP_DEFAULT_LLGR_STALE_TIME || show_defaults)
		vty_out(vty, " bgp long-lived-graceful-restart stale-time %u\n", val);
}

int bgp_nb_gr_enabled_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	int ret;

	bool enable;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	enable = yang_dnode_get_bool(args->dnode, NULL);
	bgp = nb_running_get_entry(args->dnode, NULL, true);
	ret = bgp_inst_gr_config(bgp, enable, false);
	if (ret != BGP_GR_SUCCESS) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   enable ? "Failed to enable graceful-restart"
				  : "Failed to disable graceful-restart");
		return NB_ERR;
	}
	return NB_OK;
}

int bgp_nb_gr_enabled_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	int ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	ret = bgp_inst_gr_config(bgp, false, false);
	if (ret != BGP_GR_SUCCESS) {
		snprintfrr(args->errmsg, args->errmsg_len, "Failed to disable graceful-restart");
		return NB_ERR;
	}
	return NB_OK;
}

void bgp_nb_cli_show_gr_enabled(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp graceful-restart\n");
}

int bgp_nb_gr_disable_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct listnode *node, *nnode;
	struct peer *peer;
	int ret;

	bool disable;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	disable = yang_dnode_get_bool(args->dnode, NULL);
	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!disable) {
		ret = bgp_inst_gr_config(bgp, false, true);
		if (ret != BGP_GR_SUCCESS) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "Failed to clear graceful-restart-disable");
			return NB_ERR;
		}
		return NB_OK;
	}

	ret = bgp_inst_gr_config(bgp, true, true);
	if (ret != BGP_GR_SUCCESS) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   "Failed to disable graceful-restart globally");
		return NB_ERR;
	}
	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
		bgp_capability_send(peer->connection, AFI_IP, SAFI_UNICAST,
				    CAPABILITY_CODE_RESTART, CAPABILITY_ACTION_UNSET);
		bgp_capability_send(peer->connection, AFI_IP, SAFI_UNICAST, CAPABILITY_CODE_LLGR,
				    CAPABILITY_ACTION_UNSET);
	}
	return NB_OK;
}

int bgp_nb_gr_disable_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	int ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	ret = bgp_inst_gr_config(bgp, false, true);
	if (ret != BGP_GR_SUCCESS) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   "Failed to clear graceful-restart-disable");
		return NB_ERR;
	}
	return NB_OK;
}

void bgp_nb_cli_show_gr_disable(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp graceful-restart-disable\n");
}

static void bgp_nb_tcp_keepalive_apply(struct bgp *bgp, const struct lyd_node *dnode)
{
	const struct lyd_node *ka = yang_dnode_get_parent(dnode, "tcp-keepalive");

	if (!yang_dnode_exists(ka, "idle") || !yang_dnode_exists(ka, "interval") ||
	    !yang_dnode_exists(ka, "probes"))
		return;

	bgp_tcp_keepalive_set(bgp, yang_dnode_get_uint16(ka, "idle"),
			      yang_dnode_get_uint16(ka, "interval"),
			      yang_dnode_get_uint8(ka, "probes"));
}

static void bgp_nb_tcp_keepalive_clear_if_empty(struct bgp *bgp, const struct lyd_node *dnode)
{
	const struct lyd_node *ka = yang_dnode_get_parent(dnode, "tcp-keepalive");

	if (yang_dnode_exists(ka, "idle") || yang_dnode_exists(ka, "interval") ||
	    yang_dnode_exists(ka, "probes"))
		return;

	bgp_tcp_keepalive_unset(bgp);
}

int bgp_nb_tcp_keepalive_idle_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp_nb_tcp_keepalive_apply(bgp, args->dnode);
	return NB_OK;
}

int bgp_nb_tcp_keepalive_idle_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp_nb_tcp_keepalive_clear_if_empty(bgp, args->dnode);
	return NB_OK;
}

int bgp_nb_tcp_keepalive_interval_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp_nb_tcp_keepalive_apply(bgp, args->dnode);
	return NB_OK;
}

int bgp_nb_tcp_keepalive_interval_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp_nb_tcp_keepalive_clear_if_empty(bgp, args->dnode);
	return NB_OK;
}

int bgp_nb_tcp_keepalive_probes_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp_nb_tcp_keepalive_apply(bgp, args->dnode);
	return NB_OK;
}

int bgp_nb_tcp_keepalive_probes_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp_nb_tcp_keepalive_clear_if_empty(bgp, args->dnode);
	return NB_OK;
}

void bgp_nb_cli_show_tcp_keepalive_idle(struct vty *vty, const struct lyd_node *dnode,
					bool show_defaults)
{
	const struct lyd_node *ka = yang_dnode_get_parent(dnode, "tcp-keepalive");

	if (!yang_dnode_exists(ka, "interval") || !yang_dnode_exists(ka, "probes"))
		return;

	vty_out(vty, " bgp tcp-keepalive %u %u %u\n", yang_dnode_get_uint16(dnode, NULL),
		yang_dnode_get_uint16(ka, "interval"), yang_dnode_get_uint8(ka, "probes"));
}

int bgp_nb_wpkt_quanta_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	atomic_store_explicit(&bgp->wpkt_quanta, yang_dnode_get_uint32(args->dnode, NULL),
			      memory_order_relaxed);
	return NB_OK;
}

void bgp_nb_cli_show_wpkt_quanta(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	uint32_t quanta = yang_dnode_get_uint32(dnode, NULL);

	if (quanta != BGP_WRITE_PACKET_MAX || show_defaults)
		vty_out(vty, " write-quanta %u\n", quanta);
}

int bgp_nb_rpkt_quanta_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	atomic_store_explicit(&bgp->rpkt_quanta, yang_dnode_get_uint32(args->dnode, NULL),
			      memory_order_relaxed);
	return NB_OK;
}

void bgp_nb_cli_show_rpkt_quanta(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	uint32_t quanta = yang_dnode_get_uint32(dnode, NULL);

	if (quanta != BGP_READ_PACKET_MAX || show_defaults)
		vty_out(vty, " read-quanta %u\n", quanta);
}

int bgp_nb_coalesce_time_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	uint32_t value;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	value = yang_dnode_get_uint32(args->dnode, NULL);
	if (value == BGP_DEFAULT_SUBGROUP_COALESCE_TIME) {
		bgp->heuristic_coalesce = true;
		bgp->coalesce_time = BGP_DEFAULT_SUBGROUP_COALESCE_TIME;
	} else {
		bgp->heuristic_coalesce = false;
		bgp->coalesce_time = value;
	}
	return NB_OK;
}

void bgp_nb_cli_show_coalesce_time(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults)
{
	uint32_t value = yang_dnode_get_uint32(dnode, NULL);

	if (value != BGP_DEFAULT_SUBGROUP_COALESCE_TIME || show_defaults)
		vty_out(vty, " coalesce-time %u\n", value);
}

int bgp_nb_subgroup_pkt_queue_size_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	uint32_t value;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	value = yang_dnode_get_uint32(args->dnode, NULL);
	if (value == BGP_DEFAULT_SUBGROUP_PKT_QUEUE_MAX)
		bgp_default_subgroup_pkt_queue_max_unset(bgp);
	else
		bgp_default_subgroup_pkt_queue_max_set(bgp, value);
	return NB_OK;
}

void bgp_nb_cli_show_subgroup_pkt_queue_size(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults)
{
	uint32_t value = yang_dnode_get_uint32(dnode, NULL);

	if (value != BGP_DEFAULT_SUBGROUP_PKT_QUEUE_MAX || show_defaults)
		vty_out(vty, " bgp default subgroup-pkt-queue-max %u\n", value);
}

int bgp_nb_default_originate_setonly_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_DEFAULT_ORIGINATE_SETONLY_UNCONDITIONAL);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_DEFAULT_ORIGINATE_SETONLY_UNCONDITIONAL);
	return NB_OK;
}

void bgp_nb_cli_show_default_originate_setonly(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp default-originate set-only-unconditional\n");
	else if (show_defaults)
		vty_out(vty, " no bgp default-originate set-only-unconditional\n");
}

int bgp_nb_default_shutdown_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp->autoshutdown = yang_dnode_get_bool(args->dnode, NULL);
	return NB_OK;
}

void bgp_nb_cli_show_default_shutdown(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp default shutdown\n");
	else if (show_defaults)
		vty_out(vty, " no bgp default shutdown\n");
}

/* Whether administrative shutdown should send BGP NOTIFICATION messages. */
static bool bgp_nb_shutdown_send_notify(const struct lyd_node *global)
{
	if (yang_dnode_exists(global, "shutdown-no-notify") &&
	    yang_dnode_get_bool(global, "shutdown-no-notify"))
		return false;
	return true;
}

int bgp_nb_shutdown_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const struct lyd_node *global;
	const char *msg = NULL;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	global = yang_dnode_get_parent(args->dnode, "global");
	if (yang_dnode_get_bool(args->dnode, NULL)) {
		/*
		 * If shutdown-message is in the same candidate, let its
		 * modify callback call bgp_shutdown_enable() with the text.
		 * Enabling here first with NULL makes the later call a no-op
		 * (BGP_FLAG_SHUTDOWN already set) and peers get an empty
		 * RFC 8203 message.
		 */
		if (yang_dnode_exists(global, "shutdown-message"))
			return NB_OK;
		bgp_shutdown_enable(bgp, msg, bgp_nb_shutdown_send_notify(global));
	} else
		bgp_shutdown_disable(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_shutdown(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const struct lyd_node *global = yang_dnode_get_parent(dnode, "global");

	if (!yang_dnode_get_bool(dnode, NULL))
		return;
	if (yang_dnode_exists(global, "shutdown-message"))
		return; /* shown by shutdown-message */
	if (!bgp_nb_shutdown_send_notify(global))
		return; /* shown by shutdown-no-notify */
	vty_out(vty, " bgp shutdown\n");
}

int bgp_nb_shutdown_message_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const struct lyd_node *global;
	const char *msg;

	switch (args->event) {
	case NB_EV_VALIDATE:
		msg = yang_dnode_get_string(args->dnode, NULL);
		if (strlen(msg) > BGP_ADMIN_SHUTDOWN_MSG_LEN) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "Shutdown message size exceeded %d", BGP_ADMIN_SHUTDOWN_MSG_LEN);
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	global = yang_dnode_get_parent(args->dnode, "global");
	bgp_shutdown_enable(bgp, yang_dnode_get_string(args->dnode, NULL),
			    bgp_nb_shutdown_send_notify(global));
	return NB_OK;
}

int bgp_nb_shutdown_message_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const struct lyd_node *global;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	global = yang_dnode_get_parent(args->dnode, "global");
	if (yang_dnode_exists(global, "shutdown") && yang_dnode_get_bool(global, "shutdown"))
		bgp_shutdown_enable(bgp, NULL, bgp_nb_shutdown_send_notify(global));
	return NB_OK;
}

void bgp_nb_cli_show_shutdown_message(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults)
{
	vty_out(vty, " bgp shutdown message %s\n", yang_dnode_get_string(dnode, NULL));
}

/*
 * "bgp shutdown no-notify": the value is consumed by the shutdown /
 * shutdown-message callbacks when the instance is shut down, so there is
 * nothing to do here other than accept the configuration.
 */
int bgp_nb_shutdown_no_notify_modify(struct nb_cb_modify_args *args)
{
	return NB_OK;
}

int bgp_nb_shutdown_no_notify_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

void bgp_nb_cli_show_shutdown_no_notify(struct vty *vty, const struct lyd_node *dnode,
					bool show_defaults)
{
	const struct lyd_node *global = yang_dnode_get_parent(dnode, "global");

	if (!yang_dnode_get_bool(dnode, NULL))
		return;
	if (yang_dnode_exists(global, "shutdown") && yang_dnode_get_bool(global, "shutdown"))
		vty_out(vty, " bgp shutdown no-notify\n");
}

int bgp_nb_allow_martian_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp->allow_martian = yang_dnode_get_bool(args->dnode, NULL);
	return NB_OK;
}

void bgp_nb_cli_show_allow_martian(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp allow-martian-nexthop\n");
	else if (show_defaults)
		vty_out(vty, " no bgp allow-martian-nexthop\n");
}

int bgp_nb_use_underlays_nexthop_weight_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_USE_RECURSIVE_WEIGHT);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_USE_RECURSIVE_WEIGHT);
	return NB_OK;
}

void bgp_nb_cli_show_use_underlays_nexthop_weight(struct vty *vty, const struct lyd_node *dnode,
						  bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " use-underlays-nexthop-weight\n");
	else if (show_defaults)
		vty_out(vty, " no use-underlays-nexthop-weight\n");
}

int bgp_nb_suppress_fib_pending_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	bool set;
	uint16_t delay = BGP_DEFAULT_SUPPRESS_FIB_ADV_DELAY;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	set = yang_dnode_get_bool(args->dnode, NULL);
	if (set && yang_dnode_exists(args->dnode, "../suppress-fib-pending-delay"))
		delay = yang_dnode_get_uint16(args->dnode, "../suppress-fib-pending-delay");
	else if (set)
		delay = bgp->suppress_fib_adv_delay;

	bgp_suppress_fib_pending_set(bgp, set, delay);
	return NB_OK;
}

void bgp_nb_cli_show_suppress_fib_pending(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults)
{
	/*
	 * CLI always stores delay (YANG default 1000). nb_cli_show_dnode_cmds
	 * skips the default-valued delay leaf, so its cli_show never runs.
	 * Print the enable form here when delay is absent OR at default.
	 */
	if (yang_dnode_get_bool(dnode, NULL)) {
		if (!yang_dnode_exists(dnode, "../suppress-fib-pending-delay") ||
		    yang_dnode_is_default(dnode, "../suppress-fib-pending-delay"))
			vty_out(vty, " bgp suppress-fib-pending\n");
	} else if (show_defaults)
		vty_out(vty, " no bgp suppress-fib-pending\n");
}

int bgp_nb_suppress_fib_pending_delay_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	uint16_t delay;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	delay = yang_dnode_get_uint16(args->dnode, NULL);
	bgp_suppress_fib_pending_set(bgp, true, delay);
	return NB_OK;
}

int bgp_nb_suppress_fib_pending_delay_destroy(struct nb_cb_destroy_args *args)
{
	/* Cleared via suppress-fib-pending = false. */
	return NB_OK;
}

void bgp_nb_cli_show_suppress_fib_pending_delay(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults)
{
	uint16_t delay = yang_dnode_get_uint16(dnode, NULL);

	if (delay != BGP_DEFAULT_SUPPRESS_FIB_ADV_DELAY)
		vty_out(vty, " bgp suppress-fib-pending %u\n", delay);
	else
		vty_out(vty, " bgp suppress-fib-pending\n");
}

int bgp_nb_fast_convergence_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp->fast_convergence = yang_dnode_get_bool(args->dnode, NULL);
	return NB_OK;
}

void bgp_nb_cli_show_fast_convergence(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp fast-convergence\n");
	else if (show_defaults)
		vty_out(vty, " no bgp fast-convergence\n");
}

int bgp_nb_ipv6_auto_ra_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	/* YANG true => allow RA; C flag is inverted (NO_AUTO_RA). */
	if (yang_dnode_get_bool(args->dnode, NULL))
		UNSET_FLAG(bgp->flags, BGP_FLAG_IPV6_NO_AUTO_RA);
	else
		SET_FLAG(bgp->flags, BGP_FLAG_IPV6_NO_AUTO_RA);
	return NB_OK;
}

void bgp_nb_cli_show_ipv6_auto_ra(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no bgp ipv6-auto-ra\n");
	else if (show_defaults)
		vty_out(vty, " bgp ipv6-auto-ra\n");
}

int bgp_nb_labeled_unicast_explicit_null_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *val;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	val = yang_dnode_get_string(args->dnode, NULL);

	UNSET_FLAG(bgp->flags, BGP_FLAG_LU_IPV4_EXPLICIT_NULL | BGP_FLAG_LU_IPV6_EXPLICIT_NULL);

	if (strmatch(val, "explicit-null"))
		SET_FLAG(bgp->flags,
			 BGP_FLAG_LU_IPV4_EXPLICIT_NULL | BGP_FLAG_LU_IPV6_EXPLICIT_NULL);
	else if (strmatch(val, "ipv4-explicit-null"))
		SET_FLAG(bgp->flags, BGP_FLAG_LU_IPV4_EXPLICIT_NULL);
	else if (strmatch(val, "ipv6-explicit-null"))
		SET_FLAG(bgp->flags, BGP_FLAG_LU_IPV6_EXPLICIT_NULL);

	return NB_OK;
}

void bgp_nb_cli_show_labeled_unicast_explicit_null(struct vty *vty, const struct lyd_node *dnode,
						   bool show_defaults)
{
	const char *val = yang_dnode_get_string(dnode, NULL);

	if (strmatch(val, "none")) {
		if (show_defaults)
			vty_out(vty, " no bgp labeled-unicast explicit-null\n");
		return;
	}

	vty_out(vty, " bgp labeled-unicast %s\n", val);
}

int bgp_nb_default_dynamic_capability_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_DYNAMIC_CAPABILITY);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_DYNAMIC_CAPABILITY);
	return NB_OK;
}

void bgp_nb_cli_show_default_dynamic_capability(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp default dynamic-capability\n");
	else if (show_defaults)
		vty_out(vty, " no bgp default dynamic-capability\n");
}

int bgp_nb_default_link_local_capability_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_LINK_LOCAL_CAPABILITY);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_LINK_LOCAL_CAPABILITY);
	return NB_OK;
}

void bgp_nb_cli_show_default_link_local_capability(struct vty *vty, const struct lyd_node *dnode,
						   bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp default link-local-capability\n");
	else if (show_defaults)
		vty_out(vty, " no bgp default link-local-capability\n");
}

int bgp_nb_default_software_version_capability_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *val;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	val = yang_dnode_get_string(args->dnode, NULL);

	UNSET_FLAG(bgp->flags,
		   BGP_FLAG_SOFT_VERSION_CAPABILITY_OLD | BGP_FLAG_SOFT_VERSION_CAPABILITY_NEW);

	if (strmatch(val, "old-encoding"))
		SET_FLAG(bgp->flags, BGP_FLAG_SOFT_VERSION_CAPABILITY_OLD);
	else if (strmatch(val, "latest-encoding"))
		SET_FLAG(bgp->flags, BGP_FLAG_SOFT_VERSION_CAPABILITY_NEW);

	return NB_OK;
}

void bgp_nb_cli_show_default_software_version_capability(struct vty *vty,
							 const struct lyd_node *dnode,
							 bool show_defaults)
{
	const char *val = yang_dnode_get_string(dnode, NULL);

	if (strmatch(val, "old-encoding"))
		vty_out(vty, " bgp default software-version-capability\n");
	else if (strmatch(val, "latest-encoding"))
		vty_out(vty, " bgp default software-version-capability latest-encoding\n");
	else if (show_defaults)
		vty_out(vty, " no bgp default software-version-capability\n");
}

/*
 * Helpers for remote-as mapping
 */
static int bgp_nb_parse_as_type(const char *as_type_str, enum peer_asn_type *as_type, as_t *as,
				const struct lyd_node *dnode)
{
	*as = 0;

	if (strmatch(as_type_str, "internal")) {
		*as_type = AS_INTERNAL;
	} else if (strmatch(as_type_str, "external")) {
		*as_type = AS_EXTERNAL;
	} else if (strmatch(as_type_str, "auto")) {
		*as_type = AS_AUTO;
	} else if (strmatch(as_type_str, "as-specified")) {
		*as_type = AS_SPECIFIED;
		if (!yang_dnode_exists(dnode, "../remote-as"))
			return 1; /* AS value not present yet */
		*as = yang_dnode_get_uint32(dnode, "../remote-as");
	} else {
		return -1;
	}

	return 0;
}

static void bgp_nb_fix_confed_local_as(struct peer *peer, as_t as)
{
	if (as == 0 && CHECK_FLAG(peer->bgp->config, BGP_CONFIG_CONFEDERATION))
		peer->local_as = peer->bgp->as;
}

/*
 * Numbered neighbors
 */
int bgp_nb_neighbor_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	const char *remote_addr_str;
	union sockunion su;
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
		remote_addr_str = yang_dnode_get_string(args->dnode, "./remote-address");
		if (str2sockunion(remote_addr_str, &su) < 0) {
			snprintfrr(args->errmsg, args->errmsg_len, "invalid neighbor address %s",
				   remote_addr_str);
			return NB_ERR_VALIDATION;
		}
		/* Parent BGP may only exist after APPLY in the same candidate. */
		bgp = nb_running_get_entry(lyd_parent(args->dnode), NULL, false);
		if (bgp && peer_address_self_check(bgp, &su)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "cannot configure the local system as neighbor");
			return NB_ERR_VALIDATION;
		}
		/*
		 * peer_lookup() also returns dynamic peers from "bgp listen
		 * range". Binding the YANG node to one changes its AS, and
		 * the FSM frees that peer when the session drops.
		 */
		if (bgp) {
			peer = peer_lookup(bgp, &su);
			if (peer && peer_dynamic_neighbor(peer)) {
				snprintfrr(args->errmsg, args->errmsg_len,
					   "Operation not allowed on a dynamic neighbor");
				return NB_ERR_VALIDATION;
			}
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_get_entry(lyd_parent(args->dnode), NULL, true);
	remote_addr_str = yang_dnode_get_string(args->dnode, "./remote-address");
	if (str2sockunion(remote_addr_str, &su) < 0)
		return NB_ERR_VALIDATION;

	peer = peer_lookup(bgp, &su);
	if (peer && peer_dynamic_neighbor(peer)) {
		/* VALIDATE rejects this. Do not adopt the dynamic peer. */
		return NB_OK;
	}
	if (!peer) {
		peer = peer_create(&su, NULL, bgp, bgp->as, 0, AS_UNSPECIFIED, NULL, true, NULL,
				   CONNECTION_OUTGOING);
		if (!peer)
			return NB_ERR_RESOURCE;
	}

	nb_running_set_entry(args->dnode, peer);
	return NB_OK;
}

int bgp_nb_neighbor_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer, *other;
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
		peer = nb_running_get_entry(args->dnode, NULL, false);
		if (peer && peer_dynamic_neighbor(peer)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "Operation not allowed on a dynamic neighbor");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = nb_running_get_entry(args->dnode, NULL, false);
	if (!peer)
		return NB_OK;

	/*
	 * VALIDATE rejects this. Leave the entry in place: unsetting it and
	 * then failing would drop the binding while the node stays configured.
	 */
	if (peer_dynamic_neighbor(peer))
		return NB_OK;

	nb_running_unset_entry(args->dnode);

	bgp = peer->bgp;
	other = peer->doppelganger;

	if (CHECK_FLAG(peer->flags, PEER_FLAG_CAPABILITY_ENHE) || peer->ifp)
		bgp_zebra_terminate_radv(bgp, peer);

	peer_notify_unconfig(peer->connection);
	peer_delete(peer);

	if (other && other->connection->status != Deleted) {
		peer_notify_unconfig(other->connection);
		peer_delete(other);
	}

	bgp_nb_may_stop_listening(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_neighbor(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* remote-as printed by child leaf cli_show */
}

void bgp_nb_cli_show_neighbor_end(struct vty *vty, const struct lyd_node *dnode)
{
}

/*
 * True when this neighbor's remote-as matches its peer-group (including a
 * peer-group leaf present in the same candidate). neighbor_set_peer_group_yang
 * copies the group ASN onto the neighbor because remote-as is mandatory; that
 * copy must not stamp PEER_FLAG_REMOTE_AS or peer_group_remote_as() skips the
 * member when the group remote-as later changes.
 */
static bool bgp_nb_neighbor_remote_as_matches_group(const struct lyd_node *dnode,
						    enum peer_asn_type as_type, as_t as)
{
	const struct lyd_node *nbr;
	const char *pgname;
	struct peer *peer;
	struct peer_group *group;

	nbr = yang_dnode_get_parent(dnode, "neighbor");
	if (!nbr)
		nbr = yang_dnode_get_parent(dnode, "unnumbered-neighbor");
	if (!nbr || !yang_dnode_exists(nbr, "./peer-group"))
		return false;

	pgname = yang_dnode_get_string(nbr, "./peer-group");
	peer = nb_running_get_entry_non_rec(nbr, NULL, false);
	if (!peer || !peer->bgp)
		return false;

	group = peer_group_lookup(peer->bgp, pgname);
	if (!group || !group->conf)
		return false;

	if (group->conf->as_type != as_type)
		return false;
	if (as_type == AS_SPECIFIED && group->conf->as != as)
		return false;
	return true;
}

static void bgp_nb_neighbor_remote_as_set_override(struct peer *peer, const struct lyd_node *dnode,
						   enum peer_asn_type as_type, as_t as)
{
	if (bgp_nb_neighbor_remote_as_matches_group(dnode, as_type, as))
		UNSET_FLAG(peer->flags_override, PEER_FLAG_REMOTE_AS);
	else
		SET_FLAG(peer->flags_override, PEER_FLAG_REMOTE_AS);
}

int bgp_nb_neighbor_remote_as_type_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	const char *as_type_str;
	enum peer_asn_type as_type;
	as_t as = 0;
	int ret;
	const char *as_pretty;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = nb_running_get_entry(args->dnode, NULL, true);
	as_type_str = yang_dnode_get_string(args->dnode, NULL);
	as_pretty = as_type_str;

	ret = bgp_nb_parse_as_type(as_type_str, &as_type, &as, args->dnode);
	if (ret < 0)
		return NB_ERR_VALIDATION;
	if (ret > 0)
		return NB_OK; /* as-specified without remote-as yet */

	if (as_type == AS_SPECIFIED)
		as_pretty = yang_dnode_get_string(args->dnode, "../remote-as");

	if (peer->as_type == as_type && (as_type != AS_SPECIFIED || peer->as == as)) {
		if (as_type == AS_SPECIFIED)
			bgp_nb_peer_update_as_pretty(peer, args->dnode, as);
		bgp_nb_neighbor_remote_as_set_override(peer, args->dnode, as_type, as);
		return NB_OK;
	}

	peer_as_change(peer, as, as_type, as_pretty);
	bgp_nb_neighbor_remote_as_set_override(peer, args->dnode, as_type, as);
	bgp_nb_fix_confed_local_as(peer, as);
	bgp_nb_need_listening(peer->bgp);
	return NB_OK;
}

int bgp_nb_neighbor_remote_as_type_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = nb_running_get_entry(args->dnode, NULL, false);
	if (!peer)
		return NB_OK;

	peer_as_change(peer, 0, AS_UNSPECIFIED, NULL);
	UNSET_FLAG(peer->flags_override, PEER_FLAG_REMOTE_AS);
	return NB_OK;
}

void bgp_nb_cli_show_neighbor_remote_as_type(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults)
{
	const struct lyd_node *parent;
	const char *name = NULL;
	const char *type = yang_dnode_get_string(dnode, NULL);
	bool v6only;

	parent = yang_dnode_get_parent(dnode, "neighbor");
	if (parent)
		name = yang_dnode_get_string(parent, "./remote-address");
	else {
		parent = yang_dnode_get_parent(dnode, "unnumbered-neighbor");
		if (parent) {
			/* Combined line printed by peer-group cli_show. */
			if (yang_dnode_exists(parent, "./peer-group"))
				return;
			name = yang_dnode_get_string(parent, "./interface");
			v6only = yang_dnode_exists(parent, "./v6only") &&
				 yang_dnode_get_bool(parent, "./v6only");
			if (strmatch(type, "as-specified")) {
				as_t as;
				enum asnotation_mode asnotation;

				if (!yang_dnode_exists(dnode, "../remote-as"))
					return;
				as = yang_dnode_get_uint32(dnode, "../remote-as");
				asnotation = bgp_nb_cli_dnode_asnotation(dnode);
				vty_out(vty, " neighbor %s interface%s remote-as ", name,
					v6only ? " v6only" : "");
				vty_out(vty, ASN_FORMAT(asnotation), &as);
				vty_out(vty, "\n");
			} else if (strmatch(type, "internal"))
				vty_out(vty, " neighbor %s interface%s remote-as internal\n", name,
					v6only ? " v6only" : "");
			else if (strmatch(type, "external"))
				vty_out(vty, " neighbor %s interface%s remote-as external\n", name,
					v6only ? " v6only" : "");
			else if (strmatch(type, "auto"))
				vty_out(vty, " neighbor %s interface%s remote-as auto\n", name,
					v6only ? " v6only" : "");
			return;
		}
	}
	if (!name)
		return;

	if (strmatch(type, "as-specified")) {
		as_t as;
		enum asnotation_mode asnotation;

		if (!yang_dnode_exists(dnode, "../remote-as"))
			return;
		as = yang_dnode_get_uint32(dnode, "../remote-as");
		asnotation = bgp_nb_cli_dnode_asnotation(dnode);
		vty_out(vty, " neighbor %s remote-as ", name);
		vty_out(vty, ASN_FORMAT(asnotation), &as);
		vty_out(vty, "\n");
	} else if (strmatch(type, "internal"))
		vty_out(vty, " neighbor %s remote-as internal\n", name);
	else if (strmatch(type, "external"))
		vty_out(vty, " neighbor %s remote-as external\n", name);
	else if (strmatch(type, "auto"))
		vty_out(vty, " neighbor %s remote-as auto\n", name);
}

int bgp_nb_neighbor_remote_as_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	as_t as;
	char as_buf[32];
	enum asnotation_mode asnotation;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = nb_running_get_entry(args->dnode, NULL, true);
	as = yang_dnode_get_uint32(args->dnode, NULL);

	if (peer->as_type == AS_SPECIFIED && peer->as == as) {
		bgp_nb_peer_update_as_pretty(peer, args->dnode, as);
		bgp_nb_neighbor_remote_as_set_override(peer, args->dnode, AS_SPECIFIED, as);
		return NB_OK;
	}

	asnotation = bgp_nb_cli_dnode_asnotation(args->dnode);
	snprintfrr(as_buf, sizeof(as_buf), ASN_FORMAT(asnotation), &as);
	peer_as_change(peer, as, AS_SPECIFIED, as_buf);
	bgp_nb_neighbor_remote_as_set_override(peer, args->dnode, AS_SPECIFIED, as);
	bgp_nb_need_listening(peer->bgp);
	return NB_OK;
}

int bgp_nb_neighbor_remote_as_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

/*
 * Peer-groups
 */
int bgp_nb_peer_group_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	const char *name;
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
		bgp = nb_running_get_entry(lyd_parent(args->dnode), NULL, false);
		if (!bgp)
			return NB_OK;
		name = yang_dnode_get_string(args->dnode, "./peer-group-name");
		if (peer_lookup_by_conf_if(bgp, name)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "name conflict with interface peer");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_get_entry(lyd_parent(args->dnode), NULL, true);
	name = yang_dnode_get_string(args->dnode, "./peer-group-name");

	group = peer_group_get(bgp, name);
	if (!group)
		return NB_ERR_RESOURCE;

	nb_running_set_entry(args->dnode, group);
	return NB_OK;
}

int bgp_nb_peer_group_destroy(struct nb_cb_destroy_args *args)
{
	struct peer_group *group;
	struct bgp *bgp;
	afi_t afi;

	switch (args->event) {
	case NB_EV_VALIDATE:
		group = nb_running_get_entry(args->dnode, NULL, false);
		if (!group)
			return NB_OK;
		for (afi = AFI_IP; afi < AFI_MAX; afi++) {
			if (listcount(group->listen_range[afi])) {
				snprintfrr(args->errmsg, args->errmsg_len,
					   "peer-group %s still has listen-range(s)", group->name);
				return NB_ERR_VALIDATION;
			}
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	group = nb_running_unset_entry(args->dnode);
	if (!group)
		return NB_OK;

	bgp = group->bgp;
	peer_group_notify_unconfig(group);
	peer_group_delete(group);
	bgp_nb_may_stop_listening(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_peer_group(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, " neighbor %s peer-group\n",
		yang_dnode_get_string(dnode, "./peer-group-name"));
}

void bgp_nb_cli_show_peer_group_end(struct vty *vty, const struct lyd_node *dnode)
{
}

int bgp_nb_peer_group_remote_as_type_modify(struct nb_cb_modify_args *args)
{
	struct peer_group *group;
	struct bgp *bgp;
	const char *as_type_str;
	enum peer_asn_type as_type;
	as_t as = 0;
	int ret;
	const char *as_pretty;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = nb_running_get_entry(args->dnode, NULL, true);
	bgp = group->bgp;
	as_type_str = yang_dnode_get_string(args->dnode, NULL);
	as_pretty = as_type_str;

	ret = bgp_nb_parse_as_type(as_type_str, &as_type, &as, args->dnode);
	if (ret < 0)
		return NB_ERR_VALIDATION;
	if (ret > 0)
		return NB_OK;

	if (as_type == AS_SPECIFIED)
		as_pretty = yang_dnode_get_string(args->dnode, "../remote-as");

	ret = peer_group_remote_as(bgp, group->name, &as, as_type, as_pretty);
	if (ret != 0)
		return NB_ERR_RESOURCE;

	if (as == 0 && CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION)) {
		struct listnode *node;
		struct peer *peer;

		group->conf->local_as = bgp->as;
		for (ALL_LIST_ELEMENTS_RO(group->peer, node, peer))
			peer->local_as = bgp->as;
	}

	bgp_nb_need_listening(bgp);
	return NB_OK;
}

int bgp_nb_peer_group_remote_as_type_destroy(struct nb_cb_destroy_args *args)
{
	struct peer_group *group;
	struct peer *peer;
	struct listnode *node, *nnode;
	enum peer_asn_type as_type;
	as_t as;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = nb_running_get_entry(args->dnode, NULL, true);
	if (!group)
		return NB_OK;

	as_type = group->conf->as_type;
	as = group->conf->as;

	/*
	 * YANG may stamp PEER_FLAG_REMOTE_AS on members when copying the
	 * group's AS onto the mandatory neighbor remote-as leaf. Clear that
	 * override when the member AS still matches the group so
	 * peer_group_remote_as_delete() resets the session (→ Active).
	 */
	for (ALL_LIST_ELEMENTS(group->peer, node, nnode, peer)) {
		if (!CHECK_FLAG(peer->flags_override, PEER_FLAG_REMOTE_AS))
			continue;
		if (peer->as_type != as_type)
			continue;
		if (as_type == AS_SPECIFIED && peer->as != as)
			continue;
		UNSET_FLAG(peer->flags_override, PEER_FLAG_REMOTE_AS);
	}

	peer_group_remote_as_delete(group);
	return NB_OK;
}

void bgp_nb_cli_show_peer_group_remote_as_type(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults)
{
	const char *name = yang_dnode_get_string(dnode, "../../peer-group-name");
	const char *type = yang_dnode_get_string(dnode, NULL);

	if (strmatch(type, "as-specified")) {
		as_t as;
		enum asnotation_mode asnotation;

		if (!yang_dnode_exists(dnode, "../remote-as"))
			return;
		as = yang_dnode_get_uint32(dnode, "../remote-as");
		asnotation = bgp_nb_cli_dnode_asnotation(dnode);
		vty_out(vty, " neighbor %s remote-as ", name);
		vty_out(vty, ASN_FORMAT(asnotation), &as);
		vty_out(vty, "\n");
	} else if (strmatch(type, "internal"))
		vty_out(vty, " neighbor %s remote-as internal\n", name);
	else if (strmatch(type, "external"))
		vty_out(vty, " neighbor %s remote-as external\n", name);
	else if (strmatch(type, "auto"))
		vty_out(vty, " neighbor %s remote-as auto\n", name);
}

int bgp_nb_peer_group_remote_as_modify(struct nb_cb_modify_args *args)
{
	struct peer_group *group;
	as_t as;
	const char *as_str;
	int ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = nb_running_get_entry(args->dnode, NULL, true);
	as = yang_dnode_get_uint32(args->dnode, NULL);
	as_str = yang_dnode_get_string(args->dnode, NULL);

	ret = peer_group_remote_as(group->bgp, group->name, &as, AS_SPECIFIED, as_str);
	if (ret != 0)
		return NB_ERR_RESOURCE;

	bgp_nb_need_listening(group->bgp);
	return NB_OK;
}

int bgp_nb_peer_group_remote_as_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

/*
 * peer-group listen-range leaf-lists
 */
static int bgp_nb_listen_range_parse(const struct lyd_node *dnode, struct prefix *range,
				     char *errmsg, size_t errmsg_len)
{
	if (!str2prefix(yang_dnode_get_string(dnode, NULL), range)) {
		if (errmsg)
			snprintfrr(errmsg, errmsg_len, "Malformed listen range");
		return -1;
	}
	apply_mask(range);

	if (range->family == AF_INET6 && IN6_IS_ADDR_LINKLOCAL(&range->u.prefix6)) {
		if (errmsg)
			snprintfrr(errmsg, errmsg_len,
				   "Malformed listen range (link-local address)");
		return -1;
	}
	return 0;
}

int bgp_nb_peer_group_listen_range_create(struct nb_cb_create_args *args)
{
	const struct lyd_node *pg_dnode;
	struct peer_group *group;
	struct peer_group *existing;
	struct prefix range;
	int ret;

	if (bgp_nb_listen_range_parse(args->dnode, &range, args->errmsg, args->errmsg_len) < 0)
		return NB_ERR_VALIDATION;

	pg_dnode = yang_dnode_get_parent(args->dnode, "peer-group");
	group = nb_running_get_entry(pg_dnode, NULL, args->event == NB_EV_APPLY);

	if (args->event == NB_EV_VALIDATE) {
		struct bgp *bgp;

		/*
		 * Dynamic neighbors need a remote-as, which is read from the
		 * candidate because the group and its remote-as are commonly
		 * created by the same commit as the listen range.
		 */
		if (!yang_dnode_exists(pg_dnode, "./neighbor-remote-as/remote-as-type")) {
			snprintfrr(args->errmsg, args->errmsg_len, "peer-group %s has no remote-as",
				   yang_dnode_get_string(pg_dnode, "./peer-group-name"));
			return NB_ERR_VALIDATION;
		}
		if (!group)
			return NB_OK;
		bgp = group->bgp;
		existing = bgp_listen_range_lookup(bgp, &range, true);
		if (existing && existing != group) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "Same listen range is attached to peer-group %s",
				   existing->name);
			return NB_ERR_VALIDATION;
		}
		existing = bgp_listen_range_lookup(bgp, &range, false);
		if (existing && existing != group) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "Listen range overlaps with existing listen range");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	if (!group)
		return NB_ERR_NOT_FOUND;

	ret = peer_group_listen_range_add(group, &range);
	if (ret != 0)
		return NB_ERR_RESOURCE;

	bgp_nb_need_listening(group->bgp);
	return NB_OK;
}

int bgp_nb_peer_group_listen_range_destroy(struct nb_cb_destroy_args *args)
{
	struct peer_group *group;
	struct prefix range;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	if (bgp_nb_listen_range_parse(args->dnode, &range, NULL, 0) < 0)
		return NB_OK;

	group = nb_running_get_entry(yang_dnode_get_parent(args->dnode, "peer-group"), NULL, true);
	if (!group)
		return NB_OK;

	peer_group_listen_range_del(group, &range);
	bgp_nb_may_stop_listening(group->bgp);
	return NB_OK;
}

void bgp_nb_cli_show_peer_group_listen_range(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults)
{
	const char *pg = yang_dnode_get_string(dnode, "../peer-group-name");

	vty_out(vty, " bgp listen range %s peer-group %s\n", yang_dnode_get_string(dnode, NULL),
		pg);
}

/*
 * Resolve config peer from neighbor, unnumbered-neighbor, or peer-group.
 */
static struct peer *bgp_nb_config_peer(const struct lyd_node *dnode)
{
	const struct lyd_node *list;
	struct peer_group *group;

	/*
	 * Soft, non-recursive lookup: VALIDATE runs before APPLY of list
	 * creates in the same candidate, so the peer may not be in running
	 * yet. Callers must treat NULL as "skip" during VALIDATE and as an
	 * error during APPLY.
	 *
	 * Must not use recursive nb_running_get_entry(): walking to the BGP
	 * instance would return struct bgp * cast as peer when the neighbor
	 * create is still pending, and peer->bgp would be garbage.
	 */
	list = yang_dnode_get_parent(dnode, "neighbor");
	if (list)
		return nb_running_get_entry_non_rec(list, NULL, false);

	list = yang_dnode_get_parent(dnode, "unnumbered-neighbor");
	if (list)
		return nb_running_get_entry_non_rec(list, NULL, false);

	list = yang_dnode_get_parent(dnode, "peer-group");
	if (list) {
		group = nb_running_get_entry_non_rec(list, NULL, false);
		return group ? group->conf : NULL;
	}

	return NULL;
}

static const char *bgp_nb_config_peer_name(const struct lyd_node *dnode)
{
	const struct lyd_node *list;

	list = yang_dnode_get_parent(dnode, "neighbor");
	if (list)
		return yang_dnode_get_string(list, "./remote-address");

	list = yang_dnode_get_parent(dnode, "unnumbered-neighbor");
	if (list)
		return yang_dnode_get_string(list, "./interface");

	list = yang_dnode_get_parent(dnode, "peer-group");
	if (list)
		return yang_dnode_get_string(list, "./peer-group-name");

	return "?";
}

/*
 * Unnumbered neighbors
 */
int bgp_nb_unnumbered_neighbor_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	const char *ifname;
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
		bgp = nb_running_get_entry(lyd_parent(args->dnode), NULL, false);
		if (!bgp)
			return NB_OK;
		ifname = yang_dnode_get_string(args->dnode, "./interface");
		if (peer_group_lookup(bgp, ifname)) {
			snprintfrr(args->errmsg, args->errmsg_len, "name conflict with peer-group");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_get_entry(lyd_parent(args->dnode), NULL, true);
	ifname = yang_dnode_get_string(args->dnode, "./interface");

	peer = peer_lookup_by_conf_if(bgp, ifname);
	if (!peer) {
		peer = peer_create(NULL, ifname, bgp, bgp->as, 0, AS_UNSPECIFIED, NULL, true, NULL,
				   CONNECTION_OUTGOING);
		if (!peer)
			return NB_ERR_RESOURCE;

		bgp_zebra_initiate_radv(bgp, peer);

		if (!CHECK_FLAG(peer->flags_invert, PEER_FLAG_CAPABILITY_ENHE)) {
			SET_FLAG(peer->flags, PEER_FLAG_CAPABILITY_ENHE);
			SET_FLAG(peer->flags_invert, PEER_FLAG_CAPABILITY_ENHE);
			SET_FLAG(peer->flags_override, PEER_FLAG_CAPABILITY_ENHE);
		}
	}

	nb_running_set_entry(args->dnode, peer);
	bgp_nb_need_listening(bgp);
	return NB_OK;
}

int bgp_nb_unnumbered_neighbor_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer, *other;
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = nb_running_unset_entry(args->dnode);
	if (!peer)
		return NB_OK;

	bgp = peer->bgp;
	other = peer->doppelganger;
	if (peer->ifp || CHECK_FLAG(peer->flags, PEER_FLAG_CAPABILITY_ENHE))
		bgp_zebra_terminate_radv(bgp, peer);
	peer_notify_unconfig(peer->connection);
	peer_delete(peer);
	if (other && other->connection->status != Deleted) {
		peer_notify_unconfig(other->connection);
		peer_delete(other);
	}
	bgp_nb_may_stop_listening(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_unnumbered_neighbor(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults)
{
	const char *ifname = yang_dnode_get_string(dnode, "./interface");
	bool v6only = yang_dnode_exists(dnode, "./v6only") &&
		      yang_dnode_get_bool(dnode, "./v6only");

	/*
	 * Full line (v6only / peer-group / remote-as) is composed from child
	 * cli_show callbacks; emit the base create form when nothing else
	 * prints a complete interface line. Prefer printing here only the
	 * bare interface create when no remote-as is present.
	 */
	if (!yang_dnode_exists(dnode, "./neighbor-remote-as/remote-as-type") &&
	    !yang_dnode_exists(dnode, "./peer-group")) {
		if (v6only)
			vty_out(vty, " neighbor %s interface v6only\n", ifname);
		else
			vty_out(vty, " neighbor %s interface\n", ifname);
	}
}

void bgp_nb_cli_show_unnumbered_neighbor_end(struct vty *vty, const struct lyd_node *dnode)
{
}

int bgp_nb_unnumbered_v6only_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	bool v6only;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = nb_running_get_entry(args->dnode, NULL, true);
	v6only = yang_dnode_get_bool(args->dnode, NULL);

	if (v6only == !!CHECK_FLAG(peer->flags, PEER_FLAG_IFPEER_V6ONLY))
		return NB_OK;

	if (v6only)
		peer_flag_set(peer, PEER_FLAG_IFPEER_V6ONLY);
	else
		peer_flag_unset(peer, PEER_FLAG_IFPEER_V6ONLY);

	peer_set_last_reset(peer, PEER_DOWN_V6ONLY_CHANGE);
	if (!peer_notify_config_change(peer->connection))
		bgp_session_reset(peer);

	return NB_OK;
}

void bgp_nb_cli_show_unnumbered_v6only(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults)
{
	/* Printed with interface / peer-group / remote-as composition. */
}

static bool bgp_nb_dnode_afi_safi(const struct lyd_node *dnode, afi_t *afi, safi_t *safi);
static void bgp_nb_peer_reapply_enabled_af(struct peer *peer, const struct lyd_node *pg_leaf);

int bgp_nb_unnumbered_peer_group_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	struct peer_group *group;
	const char *group_name;
	as_t as;
	int ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = nb_running_get_entry(args->dnode, NULL, true);
	group_name = yang_dnode_get_string(args->dnode, NULL);
	group = peer_group_lookup(peer->bgp, group_name);
	if (!group)
		return NB_ERR_NOT_FOUND;

	as = peer->as;
	ret = peer_group_bind(peer->bgp, NULL, peer, group, &as);
	if (ret != 0)
		return NB_ERR_RESOURCE;

	bgp_nb_peer_reapply_enabled_af(peer, args->dnode);

	return NB_OK;
}

int bgp_nb_unnumbered_peer_group_destroy(struct nb_cb_destroy_args *args)
{
	/*
	 * Same unbind as a numbered neighbor: drop the group, inherited
	 * config, and update-group membership. bgp_nb_config_peer()
	 * resolves an unnumbered-neighbor entry.
	 */
	return bgp_nb_neighbor_peer_group_destroy(args);
}

void bgp_nb_cli_show_unnumbered_peer_group(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	const char *ifname = yang_dnode_get_string(dnode, "../interface");
	const char *pg = yang_dnode_get_string(dnode, NULL);
	bool v6only = yang_dnode_exists(dnode, "../v6only") &&
		      yang_dnode_get_bool(dnode, "../v6only");
	const char *type = NULL;

	if (yang_dnode_exists(dnode, "../neighbor-remote-as/remote-as-type"))
		type = yang_dnode_get_string(dnode, "../neighbor-remote-as/remote-as-type");

	/*
	 * Prefer a single combined line when peer-group is set. Remote-as
	 * child cli_show also prints; suppress bare remote-as when we print
	 * here with peer-group. Simpler: print interface+v6only+peer-group
	 * and let remote-as cli_show print remote-as separately (classic
	 * write often splits). Match classic: one line with all options.
	 */
	vty_out(vty, " neighbor %s interface%s peer-group %s", ifname, v6only ? " v6only" : "", pg);
	if (type) {
		if (strmatch(type, "as-specified") &&
		    yang_dnode_exists(dnode, "../neighbor-remote-as/remote-as")) {
			as_t as = yang_dnode_get_uint32(dnode, "../neighbor-remote-as/remote-as");
			enum asnotation_mode asnotation = bgp_nb_cli_dnode_asnotation(dnode);

			vty_out(vty, " remote-as ");
			vty_out(vty, ASN_FORMAT(asnotation), &as);
		} else if (strmatch(type, "internal"))
			vty_out(vty, " remote-as internal");
		else if (strmatch(type, "external"))
			vty_out(vty, " remote-as external");
		else if (strmatch(type, "auto"))
			vty_out(vty, " remote-as auto");
	}
	vty_out(vty, "\n");
}

/*
 * Shared session leaves
 */
int bgp_nb_peer_password_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	int ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	ret = peer_password_set(peer, yang_dnode_get_string(args->dnode, NULL));
	return ret ? NB_ERR_RESOURCE : NB_OK;
}

int bgp_nb_peer_password_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_OK;

	peer_password_unset(peer);
	return NB_OK;
}

void bgp_nb_cli_show_peer_password(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults)
{
	vty_out(vty, " neighbor %s password %s\n", bgp_nb_config_peer_name(dnode),
		yang_dnode_get_string(dnode, NULL));
}

int bgp_nb_peer_description_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	peer_description_set(peer, yang_dnode_get_string(args->dnode, NULL));
	return NB_OK;
}

int bgp_nb_peer_description_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_OK;

	peer_description_unset(peer);
	return NB_OK;
}

void bgp_nb_cli_show_peer_description(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults)
{
	vty_out(vty, " neighbor %s description %s\n", bgp_nb_config_peer_name(dnode),
		yang_dnode_get_string(dnode, NULL));
}

int bgp_nb_peer_passive_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_set(peer, PEER_FLAG_PASSIVE);
	else
		peer_flag_unset(peer, PEER_FLAG_PASSIVE);
	return NB_OK;
}

void bgp_nb_cli_show_peer_passive(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s passive\n", bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, " no neighbor %s passive\n", bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_solo_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	update_group_adjust_soloness(peer, yang_dnode_get_bool(args->dnode, NULL));
	return NB_OK;
}

void bgp_nb_cli_show_peer_solo(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s solo\n", bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, " no neighbor %s solo\n", bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_shutdown_enable_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL)) {
		const struct lyd_node *shut;

		/*
		 * Schema order applies enable before message. The cease
		 * notification is sent from peer_flag_set(), so copy the
		 * message from the candidate first. Classic CLI does the
		 * same: peer_tx_shutdown_message_set() then the flag.
		 */
		shut = yang_dnode_get_parent(args->dnode, "admin-shutdown");
		if (shut && yang_dnode_exists(shut, "./message"))
			peer_tx_shutdown_message_set(peer,
						     yang_dnode_get_string(shut, "./message"));
		peer_flag_set(peer, PEER_FLAG_SHUTDOWN);
	} else {
		peer_tx_shutdown_message_unset(peer);
		peer_flag_unset(peer, PEER_FLAG_SHUTDOWN);
	}
	return NB_OK;
}

void bgp_nb_cli_show_peer_shutdown_enable(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults)
{
	const struct lyd_node *shut = yang_dnode_get_parent(dnode, "admin-shutdown");

	/* Message leaf prints the combined form when present. */
	if (shut && yang_dnode_exists(shut, "./message"))
		return;

	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s shutdown\n", bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, " no neighbor %s shutdown\n", bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_shutdown_message_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	peer_tx_shutdown_message_set(peer, yang_dnode_get_string(args->dnode, NULL));
	return NB_OK;
}

int bgp_nb_peer_shutdown_message_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_OK;

	peer_tx_shutdown_message_unset(peer);
	return NB_OK;
}

void bgp_nb_cli_show_peer_shutdown_message(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	vty_out(vty, " neighbor %s shutdown message %s\n", bgp_nb_config_peer_name(dnode),
		yang_dnode_get_string(dnode, NULL));
}

int bgp_nb_peer_shutdown_rtt_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	const struct lyd_node *shut;
	uint16_t rtt;
	uint8_t count = 1;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	rtt = yang_dnode_get_uint16(args->dnode, NULL);
	shut = yang_dnode_get_parent(args->dnode, "admin-shutdown");
	if (shut && yang_dnode_exists(shut, "./rtt-count"))
		count = yang_dnode_get_uint8(shut, "./rtt-count");

	peer->rtt_expected = rtt;
	peer->rtt_keepalive_conf = count;
	peer_flag_set(peer, PEER_FLAG_RTT_SHUTDOWN);
	return NB_OK;
}

int bgp_nb_peer_shutdown_rtt_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_OK;

	peer->rtt_expected = 0;
	peer->rtt_keepalive_conf = 1;
	peer_flag_unset(peer, PEER_FLAG_RTT_SHUTDOWN);
	return NB_OK;
}

void bgp_nb_cli_show_peer_shutdown_rtt(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults)
{
	const struct lyd_node *shut = yang_dnode_get_parent(dnode, "admin-shutdown");
	uint8_t count = 1;

	if (shut && yang_dnode_exists(shut, "./rtt-count"))
		count = yang_dnode_get_uint8(shut, "./rtt-count");

	vty_out(vty, " neighbor %s shutdown rtt %u count %u\n", bgp_nb_config_peer_name(dnode),
		yang_dnode_get_uint16(dnode, NULL), count);
}

int bgp_nb_peer_shutdown_rtt_count_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	peer->rtt_keepalive_conf = yang_dnode_get_uint8(args->dnode, NULL);
	return NB_OK;
}

int bgp_nb_peer_shutdown_rtt_count_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_OK;

	peer->rtt_keepalive_conf = 1;
	return NB_OK;
}

/*
 * Shared connection / timer / capability session leaves
 */
int bgp_nb_peer_update_source_ip_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	union sockunion su;
	const char *ip;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	ip = yang_dnode_get_string(args->dnode, NULL);
	if (str2sockunion(ip, &su) < 0)
		return NB_ERR_VALIDATION;

	peer_update_source_addr_set(peer, &su);
	return NB_OK;
}

int bgp_nb_peer_update_source_ip_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (peer)
		peer_update_source_unset(peer);
	return NB_OK;
}

void bgp_nb_cli_show_peer_update_source_ip(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	vty_out(vty, " neighbor %s update-source %s\n", bgp_nb_config_peer_name(dnode),
		yang_dnode_get_string(dnode, NULL));
}

int bgp_nb_peer_update_source_if_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	if (peer_update_source_if_set(peer, yang_dnode_get_string(args->dnode, NULL)))
		return NB_ERR_RESOURCE;
	return NB_OK;
}

int bgp_nb_peer_update_source_if_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (peer)
		peer_update_source_unset(peer);
	return NB_OK;
}

void bgp_nb_cli_show_peer_update_source_if(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	vty_out(vty, " neighbor %s update-source %s\n", bgp_nb_config_peer_name(dnode),
		yang_dnode_get_string(dnode, NULL));
}

int bgp_nb_peer_ebgp_mh_enabled_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
		peer = bgp_nb_config_peer(args->dnode);
		if (!peer)
			return NB_OK;
		if (peer->conf_if) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "ebgp-multihop not valid for interface peer");
			return NB_ERR_VALIDATION;
		}
		if (yang_dnode_get_bool(args->dnode, NULL) && peer_gtsm_configured(peer)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "ebgp-multihop and ttl-security are mutually exclusive");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_ebgp_multihop_set(peer, MAXTTL, true);
	else
		peer_ebgp_multihop_unset(peer, true);
	return NB_OK;
}

int bgp_nb_peer_ebgp_mh_enabled_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (peer)
		peer_ebgp_multihop_unset(peer, true);
	return NB_OK;
}

void bgp_nb_cli_show_peer_ebgp_mh_enabled(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults)
{
	const struct lyd_node *mh = yang_dnode_get_parent(dnode, "ebgp-multihop");

	if (mh && yang_dnode_exists(mh, "./multihop-ttl"))
		return;

	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s ebgp-multihop\n", bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_ebgp_mh_ttl_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	uint8_t ttl;

	switch (args->event) {
	case NB_EV_VALIDATE:
		peer = bgp_nb_config_peer(args->dnode);
		if (!peer)
			return NB_OK;
		if (peer->conf_if) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "ebgp-multihop not valid for interface peer");
			return NB_ERR_VALIDATION;
		}
		if (peer_gtsm_configured(peer)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "ebgp-multihop and ttl-security are mutually exclusive");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	ttl = yang_dnode_get_uint8(args->dnode, NULL);
	peer_ebgp_multihop_set(peer, ttl, true);
	return NB_OK;
}

int bgp_nb_peer_ebgp_mh_ttl_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (peer)
		peer_ebgp_multihop_unset(peer, true);
	return NB_OK;
}

void bgp_nb_cli_show_peer_ebgp_mh_ttl(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults)
{
	vty_out(vty, " neighbor %s ebgp-multihop %u\n", bgp_nb_config_peer_name(dnode),
		yang_dnode_get_uint8(dnode, NULL));
}

int bgp_nb_peer_disable_connected_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_set(peer, PEER_FLAG_DISABLE_CONNECTED_CHECK);
	else
		peer_flag_unset(peer, PEER_FLAG_DISABLE_CONNECTED_CHECK);
	return NB_OK;
}

void bgp_nb_cli_show_peer_disable_connected(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s disable-connected-check\n",
			bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, " no neighbor %s disable-connected-check\n",
			bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_ttl_security_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	uint8_t hops;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
		peer = bgp_nb_config_peer(args->dnode);
		if (!peer)
			return NB_OK;
		hops = yang_dnode_get_uint8(args->dnode, NULL);
		if (peer->conf_if && hops > 1) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "interface peer hops cannot exceed 1");
			return NB_ERR_VALIDATION;
		}
		/*
		 * Mutual exclusion with ebgp-multihop must be enforced in
		 * VALIDATE: APPLY-time rejection cannot block the commit, and
		 * a local-as override may have temporarily sorted the peer as
		 * iBGP while cfg_ttl still records operator multihop.
		 */
		if (peer_ebgp_multihop_cfg(peer)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "%%Cannot configure both ttl-security hops and ebgp-multihop");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	ret = peer_ttl_security_hops_set(peer, yang_dnode_get_uint8(args->dnode, NULL));
	if (ret == BGP_ERR_NO_EBGP_MULTIHOP_WITH_TTLHACK) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   "%%Cannot configure both ttl-security hops and ebgp-multihop");
		return NB_ERR_RESOURCE;
	}
	if (ret)
		return NB_ERR_RESOURCE;
	return NB_OK;
}

int bgp_nb_peer_ttl_security_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (peer)
		peer_ttl_security_hops_unset(peer);
	return NB_OK;
}

void bgp_nb_cli_show_peer_ttl_security(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults)
{
	vty_out(vty, " neighbor %s ttl-security hops %u\n", bgp_nb_config_peer_name(dnode),
		yang_dnode_get_uint8(dnode, NULL));
}

static int bgp_nb_peer_local_as_apply(struct peer *peer, const struct lyd_node *dnode,
				      char *errmsg, size_t errmsg_len)
{
	const struct lyd_node *las;
	as_t as;
	bool no_prepend = false, replace_as = false, dual_as = false;
	const char *as_str;
	int ret;

	las = yang_dnode_get_parent(dnode, "local-as");
	if (!las || !yang_dnode_exists(las, "./local-as"))
		return NB_OK;

	as = yang_dnode_get_uint32(las, "./local-as");
	as_str = yang_dnode_get_string(las, "./local-as");
	if (yang_dnode_exists(las, "./no-prepend"))
		no_prepend = yang_dnode_get_bool(las, "./no-prepend");
	if (yang_dnode_exists(las, "./replace-as"))
		replace_as = yang_dnode_get_bool(las, "./replace-as");
	if (yang_dnode_exists(las, "./dual-as"))
		dual_as = yang_dnode_get_bool(las, "./dual-as");

	ret = peer_local_as_set(peer, as, no_prepend, replace_as, dual_as, as_str);
	if (ret == BGP_ERR_CANNOT_HAVE_LOCAL_AS_SAME_AS) {
		if (errmsg)
			snprintfrr(errmsg, errmsg_len,
				   "Cannot have local-as same as BGP AS number");
		return NB_ERR_VALIDATION;
	}
	if (ret < 0) {
		if (errmsg)
			snprintfrr(errmsg, errmsg_len, "Failed to set local-as");
		return NB_ERR_RESOURCE;
	}
	return NB_OK;
}

int bgp_nb_peer_local_as_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	as_t as, bgp_as;
	const struct lyd_node *bgp_dnode;

	switch (args->event) {
	case NB_EV_VALIDATE:
		as = yang_dnode_get_uint32(args->dnode, NULL);
		/*
		 * Always prefer the candidate instance AS (./global/local-as).
		 * Same-transaction "router bgp 110" + "neighbor … local-as 110"
		 * must fail VALIDATE even when the peer already exists with a
		 * different running AS (checking peer->bgp->as alone wrongly
		 * returns NB_OK and the batch commits).
		 */
		bgp_dnode = yang_dnode_get_parent(args->dnode, "bgp");
		if (bgp_dnode && yang_dnode_exists(bgp_dnode, "./global/local-as")) {
			bgp_as = yang_dnode_get_uint32(bgp_dnode, "./global/local-as");
			if (bgp_as == as) {
				snprintfrr(args->errmsg, args->errmsg_len,
					   "Cannot have local-as same as BGP AS number");
				return NB_ERR_VALIDATION;
			}
			return NB_OK;
		}
		peer = bgp_nb_config_peer(args->dnode);
		if (peer && peer->bgp && peer->bgp->as == as) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "Cannot have local-as same as BGP AS number");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	return bgp_nb_peer_local_as_apply(peer, args->dnode, args->errmsg, args->errmsg_len);
}

int bgp_nb_peer_local_as_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (peer)
		peer_local_as_unset(peer);
	return NB_OK;
}

void bgp_nb_cli_show_peer_local_as(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults)
{
	const struct lyd_node *las = yang_dnode_get_parent(dnode, "local-as");
	bool no_prepend = las && yang_dnode_exists(las, "./no-prepend") &&
			  yang_dnode_get_bool(las, "./no-prepend");
	bool replace_as = las && yang_dnode_exists(las, "./replace-as") &&
			  yang_dnode_get_bool(las, "./replace-as");
	bool dual_as = las && yang_dnode_exists(las, "./dual-as") &&
		       yang_dnode_get_bool(las, "./dual-as");
	as_t as = yang_dnode_get_uint32(dnode, NULL);
	enum asnotation_mode asnotation = bgp_nb_cli_dnode_asnotation(dnode);

	vty_out(vty, " neighbor %s local-as ", bgp_nb_config_peer_name(dnode));
	vty_out(vty, ASN_FORMAT(asnotation), &as);
	if (no_prepend)
		vty_out(vty, " no-prepend");
	if (replace_as)
		vty_out(vty, " replace-as");
	if (dual_as)
		vty_out(vty, " dual-as");
	vty_out(vty, "\n");
}

int bgp_nb_peer_local_as_no_prepend_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	return bgp_nb_peer_local_as_apply(peer, args->dnode, args->errmsg, args->errmsg_len);
}

int bgp_nb_peer_local_as_replace_as_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	return bgp_nb_peer_local_as_apply(peer, args->dnode, args->errmsg, args->errmsg_len);
}

int bgp_nb_peer_local_as_dual_as_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	return bgp_nb_peer_local_as_apply(peer, args->dnode, args->errmsg, args->errmsg_len);
}

static bool bgp_nb_timer_leaf_implicit(const struct lyd_node *timers, const char *path)
{
	const struct lyd_node *leaf;

	if (!timers || !yang_dnode_exists(timers, path))
		return true;

	leaf = yang_dnode_get(timers, path);
	return CHECK_FLAG(leaf->flags, LYD_DEFAULT);
}

/*
 * "no neighbor X timers" deletes both leaves. They have YANG defaults, so
 * the diff arrives as MODIFY back to 60/180 with LYD_DEFAULT set. That is
 * not an explicit "timers 60 180", which must still override "timers bgp".
 */
static bool bgp_nb_peer_timers_implicit(const struct lyd_node *dnode)
{
	const struct lyd_node *timers = yang_dnode_get_parent(dnode, "timers");

	return bgp_nb_timer_leaf_implicit(timers, "./keepalive") &&
	       bgp_nb_timer_leaf_implicit(timers, "./hold-time");
}

static int bgp_nb_peer_timers_validate(const struct lyd_node *dnode, char *errmsg,
				       size_t errmsg_len)
{
	const struct lyd_node *timers;
	uint32_t holdtime;

	timers = yang_dnode_get_parent(dnode, "timers");
	if (!timers || !yang_dnode_exists(timers, "./hold-time"))
		return NB_OK;

	holdtime = yang_dnode_get_uint16(timers, "./hold-time");
	if (holdtime < 3 && holdtime != 0) {
		snprintfrr(errmsg, errmsg_len,
			   "hold time value must be either 0 or greater than 3");
		return NB_ERR_VALIDATION;
	}

	return NB_OK;
}

static int bgp_nb_peer_timers_apply(const struct lyd_node *dnode)
{
	struct peer *peer;
	const struct lyd_node *timers;
	uint32_t keepalive, holdtime;

	peer = bgp_nb_config_peer(dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	if (bgp_nb_peer_timers_implicit(dnode)) {
		peer_timers_unset(peer);
		return NB_OK;
	}

	timers = yang_dnode_get_parent(dnode, "timers");
	keepalive = yang_dnode_get_uint16(timers, "./keepalive");
	holdtime = yang_dnode_get_uint16(timers, "./hold-time");
	peer_timers_set(peer, keepalive, holdtime);
	return NB_OK;
}

int bgp_nb_peer_timers_keepalive_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_nb_peer_timers_validate(args->dnode, args->errmsg, args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	return bgp_nb_peer_timers_apply(args->dnode);
}

int bgp_nb_peer_timers_keepalive_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (peer)
		peer_timers_unset(peer);
	return NB_OK;
}

void bgp_nb_cli_show_peer_timers_keepalive(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	const struct lyd_node *timers = yang_dnode_get_parent(dnode, "timers");
	uint16_t hold = 0;

	if (timers && yang_dnode_exists(timers, "./hold-time"))
		hold = yang_dnode_get_uint16(timers, "./hold-time");

	vty_out(vty, " neighbor %s timers %u %u\n", bgp_nb_config_peer_name(dnode),
		yang_dnode_get_uint16(dnode, NULL), hold);
}

void bgp_nb_cli_show_peer_timers_holdtime(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults)
{
	const struct lyd_node *timers = yang_dnode_get_parent(dnode, "timers");
	const struct lyd_node *ka;
	uint16_t keepalive;

	/*
	 * Keepalive owns this line when nb_cli_show will visit it. A default
	 * keepalive is skipped, which dropped "neighbor A timers 60 <hold>".
	 */
	ka = (timers && yang_dnode_exists(timers, "./keepalive"))
		? yang_dnode_get(timers, "./keepalive")
		: NULL;
	if (ka && (show_defaults || !yang_dnode_is_default(ka, NULL)))
		return;

	keepalive = ka ? yang_dnode_get_uint16(ka, NULL) : DFLT_BGP_KEEPALIVE;
	vty_out(vty, " neighbor %s timers %u %u\n", bgp_nb_config_peer_name(dnode), keepalive,
		yang_dnode_get_uint16(dnode, NULL));
}

int bgp_nb_peer_timers_holdtime_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_nb_peer_timers_validate(args->dnode, args->errmsg, args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	return bgp_nb_peer_timers_apply(args->dnode);
}

int bgp_nb_peer_timers_holdtime_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (peer)
		peer_timers_unset(peer);
	return NB_OK;
}

int bgp_nb_peer_timers_connect_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	peer_timers_connect_set(peer, yang_dnode_get_uint16(args->dnode, NULL));
	return NB_OK;
}

int bgp_nb_peer_timers_connect_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (peer)
		peer_timers_connect_unset(peer);
	return NB_OK;
}

void bgp_nb_cli_show_peer_timers_connect(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults)
{
	vty_out(vty, " neighbor %s timers connect %u\n", bgp_nb_config_peer_name(dnode),
		yang_dnode_get_uint16(dnode, NULL));
}

int bgp_nb_peer_timers_delayopen_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	peer_timers_delayopen_set(peer, yang_dnode_get_uint16(args->dnode, NULL));
	return NB_OK;
}

int bgp_nb_peer_timers_delayopen_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (peer)
		peer_timers_delayopen_unset(peer);
	return NB_OK;
}

void bgp_nb_cli_show_peer_timers_delayopen(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	vty_out(vty, " neighbor %s timers delayopen %u\n", bgp_nb_config_peer_name(dnode),
		yang_dnode_get_uint16(dnode, NULL));
}

int bgp_nb_peer_advertise_interval_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	peer_advertise_interval_set(peer, yang_dnode_get_uint16(args->dnode, NULL));
	return NB_OK;
}

int bgp_nb_peer_advertise_interval_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (peer)
		peer_advertise_interval_unset(peer);
	return NB_OK;
}

void bgp_nb_cli_show_peer_advertise_interval(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults)
{
	vty_out(vty, " neighbor %s advertisement-interval %u\n", bgp_nb_config_peer_name(dnode),
		yang_dnode_get_uint16(dnode, NULL));
}

int bgp_nb_peer_cap_dynamic_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_set(peer, PEER_FLAG_DYNAMIC_CAPABILITY);
	else
		peer_flag_unset(peer, PEER_FLAG_DYNAMIC_CAPABILITY);
	return NB_OK;
}

void bgp_nb_cli_show_peer_cap_dynamic(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s capability dynamic\n", bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, " no neighbor %s capability dynamic\n",
			bgp_nb_config_peer_name(dnode));
}

/*
 * Send a dynamic Capability on the peer(s) that own the TCP session.
 * Peer-group templates stay Idle; members in peer->group->peer are Established.
 * Mirrors bgp_vty_capability_send_dynamic_peer_group() in bgp_vty.c.
 */
static void bgp_nb_capability_send(struct peer *peer, int capability_code, int action)
{
	struct listnode *node;
	struct peer *member;
	struct peer_group *pg;

	if (!peer)
		return;

	if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		pg = peer->group;
		if (!pg)
			return;
		for (ALL_LIST_ELEMENTS_RO(pg->peer, node, member))
			bgp_capability_send(member->connection, AFI_IP, SAFI_UNICAST,
					    capability_code, action);
	} else {
		bgp_capability_send(peer->connection, AFI_IP, SAFI_UNICAST, capability_code,
				    action);
	}
}

int bgp_nb_peer_cap_enhe_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (!yang_dnode_get_bool(args->dnode, NULL) &&
		    yang_dnode_get_parent(args->dnode, "unnumbered-neighbor")) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "Peer %s cannot have capability extended-nexthop turned off",
				   bgp_nb_config_peer_name(args->dnode));
			return NB_ERR_VALIDATION;
		}
		peer = bgp_nb_config_peer(args->dnode);
		if (!yang_dnode_get_bool(args->dnode, NULL) && peer && peer->conf_if) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "Peer %s cannot have capability extended-nexthop turned off",
				   peer->host);
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL)) {
		peer_flag_set(peer, PEER_FLAG_CAPABILITY_ENHE);
		bgp_nb_capability_send(peer, CAPABILITY_CODE_ENHE, CAPABILITY_ACTION_SET);
	} else {
		/*
		 * Send UNSET while PEER_FLAG_CAPABILITY_ENHE is still set;
		 * bgp_capability_send() only encodes ENHE TLVs when that flag
		 * is set (same order as no_neighbor_capability_enhe).
		 */
		bgp_nb_capability_send(peer, CAPABILITY_CODE_ENHE, CAPABILITY_ACTION_UNSET);
		peer_flag_unset(peer, PEER_FLAG_CAPABILITY_ENHE);
	}
	return NB_OK;
}

void bgp_nb_cli_show_peer_cap_enhe(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s capability extended-nexthop\n",
			bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, " no neighbor %s capability extended-nexthop\n",
			bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_cap_negotiate_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	/* true => negotiate (clear DONT_CAPABILITY) */
	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_unset(peer, PEER_FLAG_DONT_CAPABILITY);
	else
		peer_flag_set(peer, PEER_FLAG_DONT_CAPABILITY);
	return NB_OK;
}

void bgp_nb_cli_show_peer_cap_negotiate(struct vty *vty, const struct lyd_node *dnode,
					bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s dont-capability-negotiate\n",
			bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, " no neighbor %s dont-capability-negotiate\n",
			bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_cap_fqdn_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	bool enable;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	enable = yang_dnode_get_bool(args->dnode, NULL);
	if (enable)
		peer_flag_set(peer, PEER_FLAG_CAPABILITY_FQDN);
	else
		peer_flag_unset(peer, PEER_FLAG_CAPABILITY_FQDN);

	bgp_nb_capability_send(peer, CAPABILITY_CODE_FQDN,
			       enable ? CAPABILITY_ACTION_SET : CAPABILITY_ACTION_UNSET);
	return NB_OK;
}

void bgp_nb_cli_show_peer_cap_fqdn(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults)
{
	/* Default is true (matches peer_create); only emit non-default. */
	if (yang_dnode_get_bool(dnode, NULL)) {
		if (show_defaults)
			vty_out(vty, " neighbor %s capability fqdn\n",
				bgp_nb_config_peer_name(dnode));
	} else
		vty_out(vty, " no neighbor %s capability fqdn\n", bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_enforce_first_as_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_set(peer, PEER_FLAG_ENFORCE_FIRST_AS);
	else
		peer_flag_unset(peer, PEER_FLAG_ENFORCE_FIRST_AS);
	return NB_OK;
}

void bgp_nb_cli_show_peer_enforce_first_as(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL)) {
		if (show_defaults)
			vty_out(vty, " neighbor %s enforce-first-as\n",
				bgp_nb_config_peer_name(dnode));
	} else
		vty_out(vty, " no neighbor %s enforce-first-as\n", bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_cap_soft_version_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	const char *val;
	bool enable;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	val = yang_dnode_get_string(args->dnode, NULL);
	/* Clear both encodings separately so peer_flag_* finds each flag. */
	peer_flag_unset(peer, PEER_FLAG_CAPABILITY_SOFT_VERSION_OLD);
	peer_flag_unset(peer, PEER_FLAG_CAPABILITY_SOFT_VERSION_NEW);
	if (strmatch(val, "old-encoding"))
		peer_flag_set(peer, PEER_FLAG_CAPABILITY_SOFT_VERSION_OLD);
	else if (strmatch(val, "latest-encoding"))
		peer_flag_set(peer, PEER_FLAG_CAPABILITY_SOFT_VERSION_NEW);
	/*
	 * "disabled" leaves whatever peer_flag_unset just did. A standalone
	 * peer loses the flag, which is how "no neighbor capability
	 * software-version" overrides bgp default software-version-capability.
	 * A group member inherits the group. Do not set flags_override here:
	 * that marks the peer-group overridden and undoes the member inherit.
	 */

	enable = CHECK_FLAG(peer->flags, PEER_FLAG_CAPABILITY_SOFT_VERSION_OLD) ||
		 CHECK_FLAG(peer->flags, PEER_FLAG_CAPABILITY_SOFT_VERSION_NEW);
	bgp_nb_capability_send(peer, CAPABILITY_CODE_SOFT_VERSION,
			       enable ? CAPABILITY_ACTION_SET : CAPABILITY_ACTION_UNSET);
	return NB_OK;
}

int bgp_nb_peer_cap_soft_version_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_OK;

	/* Leaf gone → inherit from bgp default again. */
	UNSET_FLAG(peer->flags_override, PEER_FLAG_CAPABILITY_SOFT_VERSION_OLD);
	UNSET_FLAG(peer->flags_override, PEER_FLAG_CAPABILITY_SOFT_VERSION_NEW);
	peer_flag_unset(peer, PEER_FLAG_CAPABILITY_SOFT_VERSION_OLD);
	peer_flag_unset(peer, PEER_FLAG_CAPABILITY_SOFT_VERSION_NEW);
	if (CHECK_FLAG(peer->bgp->flags, BGP_FLAG_SOFT_VERSION_CAPABILITY_OLD))
		peer_flag_set(peer, PEER_FLAG_CAPABILITY_SOFT_VERSION_OLD);
	if (CHECK_FLAG(peer->bgp->flags, BGP_FLAG_SOFT_VERSION_CAPABILITY_NEW))
		peer_flag_set(peer, PEER_FLAG_CAPABILITY_SOFT_VERSION_NEW);

	bgp_nb_capability_send(peer, CAPABILITY_CODE_SOFT_VERSION,
			       (CHECK_FLAG(peer->flags, PEER_FLAG_CAPABILITY_SOFT_VERSION_OLD) ||
				CHECK_FLAG(peer->flags, PEER_FLAG_CAPABILITY_SOFT_VERSION_NEW))
				       ? CAPABILITY_ACTION_SET
				       : CAPABILITY_ACTION_UNSET);
	return NB_OK;
}

void bgp_nb_cli_show_peer_cap_soft_version(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	const char *val = yang_dnode_get_string(dnode, NULL);

	if (strmatch(val, "old-encoding"))
		vty_out(vty, " neighbor %s capability software-version\n",
			bgp_nb_config_peer_name(dnode));
	else if (strmatch(val, "latest-encoding"))
		vty_out(vty, " neighbor %s capability software-version latest-encoding\n",
			bgp_nb_config_peer_name(dnode));
	else
		vty_out(vty, " no neighbor %s capability software-version\n",
			bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_cap_link_local_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	bool enable;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	enable = yang_dnode_get_bool(args->dnode, NULL);
	if (enable)
		peer_flag_set(peer, PEER_FLAG_CAPABILITY_LINK_LOCAL);
	else
		peer_flag_unset(peer, PEER_FLAG_CAPABILITY_LINK_LOCAL);

	bgp_nb_capability_send(peer, CAPABILITY_CODE_LINK_LOCAL,
			       enable ? CAPABILITY_ACTION_SET : CAPABILITY_ACTION_UNSET);
	return NB_OK;
}

void bgp_nb_cli_show_peer_cap_link_local(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s capability link-local\n",
			bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, " no neighbor %s capability link-local\n",
			bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_cap_override_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_set(peer, PEER_FLAG_OVERRIDE_CAPABILITY);
	else
		peer_flag_unset(peer, PEER_FLAG_OVERRIDE_CAPABILITY);
	return NB_OK;
}

void bgp_nb_cli_show_peer_cap_override(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s override-capability\n", bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, " no neighbor %s override-capability\n",
			bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_cap_strict_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_set(peer, PEER_FLAG_STRICT_CAP_MATCH);
	else
		peer_flag_unset(peer, PEER_FLAG_STRICT_CAP_MATCH);
	return NB_OK;
}

void bgp_nb_cli_show_peer_cap_strict(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s strict-capability-match\n",
			bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, " no neighbor %s strict-capability-match\n",
			bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_tcp_mss_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	peer_tcp_mss_set(peer, yang_dnode_get_uint16(args->dnode, NULL));
	return NB_OK;
}

int bgp_nb_peer_tcp_mss_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (peer)
		peer_tcp_mss_unset(peer);
	return NB_OK;
}

void bgp_nb_cli_show_peer_tcp_mss(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, " neighbor %s tcp-mss %u\n", bgp_nb_config_peer_name(dnode),
		yang_dnode_get_uint16(dnode, NULL));
}

int bgp_nb_peer_ip_transparent_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
		peer = bgp_nb_config_peer(args->dnode);
		if (!peer)
			return NB_OK;
		if (yang_dnode_get_bool(args->dnode, NULL) &&
		    !peergroup_flag_check(peer, PEER_FLAG_UPDATE_SOURCE)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "ip-transparent requires update-source");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_set(peer, PEER_FLAG_IP_TRANSPARENT);
	else
		peer_flag_unset(peer, PEER_FLAG_IP_TRANSPARENT);
	return NB_OK;
}

void bgp_nb_cli_show_peer_ip_transparent(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s ip-transparent\n", bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, " no neighbor %s ip-transparent\n", bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_rpki_strict_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_set(peer, PEER_FLAG_RPKI_STRICT);
	else
		peer_flag_unset(peer, PEER_FLAG_RPKI_STRICT);
	return NB_OK;
}

void bgp_nb_cli_show_peer_rpki_strict(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s rpki strict\n", bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, " no neighbor %s rpki strict\n", bgp_nb_config_peer_name(dnode));
}

static bool bgp_nb_role_from_str(const char *role_str, uint8_t *role)
{
	if (strmatch(role_str, "provider"))
		*role = ROLE_PROVIDER;
	else if (strmatch(role_str, "rs-server"))
		*role = ROLE_RS_SERVER;
	else if (strmatch(role_str, "rs-client"))
		*role = ROLE_RS_CLIENT;
	else if (strmatch(role_str, "customer"))
		*role = ROLE_CUSTOMER;
	else if (strmatch(role_str, "peer"))
		*role = ROLE_PEER;
	else
		return false;

	return true;
}

static enum bgp_peer_sort bgp_nb_candidate_peer_sort(const struct lyd_node *dnode);

static int bgp_nb_peer_local_role_validate(const struct lyd_node *dnode, char *errmsg,
					   size_t errmsg_len)
{
	enum bgp_peer_sort sort;
	bool group;

	group = yang_dnode_get_parent(dnode, "peer-group") != NULL;
	sort = bgp_nb_candidate_peer_sort(dnode);

	/*
	 * An untyped peer-group is allowed; members are checked when they
	 * are bound. A neighbor, or a group that is already iBGP, is not.
	 */
	if ((!group && sort != BGP_PEER_EBGP) || (group && sort == BGP_PEER_IBGP)) {
		snprintfrr(errmsg, errmsg_len, "External roles can be set only on eBGP session");
		return NB_ERR_VALIDATION;
	}

	return NB_OK;
}

static void bgp_nb_peer_local_role_apply(struct peer *peer, const struct lyd_node *dnode)
{
	const struct lyd_node *lr;
	const char *role_str;
	bool strict = false;
	uint8_t role;

	lr = yang_dnode_get_parent(dnode, "local-role");
	if (!lr || !yang_dnode_exists(lr, "./role"))
		return;

	role_str = yang_dnode_get_string(lr, "./role");
	if (!bgp_nb_role_from_str(role_str, &role))
		return;

	if (yang_dnode_exists(lr, "./strict-mode"))
		strict = yang_dnode_get_bool(lr, "./strict-mode");

	if (peer_role_set(peer, role, strict) != CMD_SUCCESS) {
		zlog_warn("%s: local-role rejected for peer %s", __func__, peer->host);
		return;
	}

	bgp_vty_role_update(peer, CAPABILITY_ACTION_SET);
}

int bgp_nb_peer_local_role_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_nb_peer_local_role_validate(args->dnode, args->errmsg, args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	bgp_nb_peer_local_role_apply(peer, args->dnode);
	return NB_OK;
}

int bgp_nb_peer_local_role_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_OK;

	peer_role_unset(peer);
	bgp_vty_role_update(peer, CAPABILITY_ACTION_UNSET);
	return NB_OK;
}

void bgp_nb_cli_show_peer_local_role(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults)
{
	const struct lyd_node *lr = yang_dnode_get_parent(dnode, "local-role");
	bool strict = lr && yang_dnode_exists(lr, "./strict-mode") &&
		      yang_dnode_get_bool(lr, "./strict-mode");

	vty_out(vty, " neighbor %s local-role %s%s\n", bgp_nb_config_peer_name(dnode),
		yang_dnode_get_string(dnode, NULL), strict ? " strict-mode" : "");
}

int bgp_nb_peer_local_role_strict_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_nb_peer_local_role_validate(args->dnode, args->errmsg, args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	bgp_nb_peer_local_role_apply(peer, args->dnode);
	return NB_OK;
}

static void bgp_nb_peer_bfd_apply(struct peer *peer)
{
	if (peer->bfd_config)
		bgp_peer_config_apply(peer, peer->group);
}

int bgp_nb_peer_bfd_enable_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL)) {
		bgp_bfd_enable(peer);
		bgp_nb_peer_bfd_apply(peer);
	} else
		bgp_peer_remove_bfd_config(peer);
	return NB_OK;
}

int bgp_nb_peer_bfd_enable_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (peer)
		bgp_peer_remove_bfd_config(peer);
	return NB_OK;
}

void bgp_nb_cli_show_peer_bfd_enable(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults)
{
	const struct lyd_node *bfd = yang_dnode_get_parent(dnode, "bfd-options");
	uint8_t mult = BFD_DEF_DETECT_MULT;
	uint16_t min_rx = BFD_DEF_MIN_RX, min_tx = BFD_DEF_MIN_TX;

	if (!yang_dnode_get_bool(dnode, NULL))
		return;

	if (bfd && yang_dnode_exists(bfd, "./detect-multiplier"))
		mult = yang_dnode_get_uint8(bfd, "./detect-multiplier");
	if (bfd && yang_dnode_exists(bfd, "./required-min-rx"))
		min_rx = yang_dnode_get_uint16(bfd, "./required-min-rx");
	if (bfd && yang_dnode_exists(bfd, "./desired-min-tx"))
		min_tx = yang_dnode_get_uint16(bfd, "./desired-min-tx");

	/*
	 * Print the whole line here. detect-multiplier's cli_show is not
	 * called when the multiplier is 3: lyd_is_default() treats an explicit
	 * 3 as the default, so "neighbor X bfd 3 100 100" would otherwise
	 * disappear from the running configuration.
	 */
	if (mult != BFD_DEF_DETECT_MULT || min_rx != BFD_DEF_MIN_RX || min_tx != BFD_DEF_MIN_TX)
		vty_out(vty, " neighbor %s bfd %u %u %u\n", bgp_nb_config_peer_name(dnode), mult,
			min_rx, min_tx);
	else
		vty_out(vty, " neighbor %s bfd\n", bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_bfd_detect_mult_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	bgp_bfd_enable(peer);
	peer->bfd_config->detection_multiplier = yang_dnode_get_uint8(args->dnode, NULL);
	bgp_nb_peer_bfd_apply(peer);
	return NB_OK;
}

int bgp_nb_peer_bfd_min_rx_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	bgp_bfd_enable(peer);
	peer->bfd_config->min_rx = yang_dnode_get_uint16(args->dnode, NULL);
	bgp_nb_peer_bfd_apply(peer);
	return NB_OK;
}

int bgp_nb_peer_bfd_min_tx_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	bgp_bfd_enable(peer);
	peer->bfd_config->min_tx = yang_dnode_get_uint16(args->dnode, NULL);
	bgp_nb_peer_bfd_apply(peer);
	return NB_OK;
}

int bgp_nb_peer_bfd_cbit_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	bgp_bfd_enable(peer);
	peer->bfd_config->cbit = yang_dnode_get_bool(args->dnode, NULL);
	bgp_nb_peer_bfd_apply(peer);
	return NB_OK;
}

void bgp_nb_cli_show_peer_bfd_cbit(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s bfd check-control-plane-failure\n",
			bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_bfd_profile_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	bgp_bfd_enable(peer);
	strlcpy(peer->bfd_config->profile, yang_dnode_get_string(args->dnode, NULL),
		sizeof(peer->bfd_config->profile));
	bgp_nb_peer_bfd_apply(peer);
	return NB_OK;
}

int bgp_nb_peer_bfd_profile_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !peer->bfd_config)
		return NB_OK;

	peer->bfd_config->profile[0] = 0;
	bgp_nb_peer_bfd_apply(peer);
	return NB_OK;
}

void bgp_nb_cli_show_peer_bfd_profile(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults)
{
	vty_out(vty, " neighbor %s bfd profile %s\n", bgp_nb_config_peer_name(dnode),
		yang_dnode_get_string(dnode, NULL));
}

int bgp_nb_peer_bfd_strict_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer, *member;
	struct listnode *node;
	bool strict;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	strict = yang_dnode_get_bool(args->dnode, NULL);
	if (strict)
		peer_flag_set(peer, PEER_FLAG_BFD_STRICT);
	else
		peer_flag_unset(peer, PEER_FLAG_BFD_STRICT);

	/*
	 * A single-hop session whose egress is still unknown stays out of
	 * bfdd. Setting the flag does not retry that install, so BGP waits
	 * for BFD and BFD waits for an interface that appears only once BGP
	 * connects. Strict mode has to install the session now.
	 */
	if (!strict)
		return NB_OK;

	if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		for (ALL_LIST_ELEMENTS_RO(peer->group->peer, node, member))
			bgp_peer_bfd_update_source(member);
	} else
		bgp_peer_bfd_update_source(peer);
	return NB_OK;
}

void bgp_nb_cli_show_peer_bfd_strict(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults)
{
	const struct lyd_node *bfd = yang_dnode_get_parent(dnode, "bfd-options");

	if (!yang_dnode_get_bool(dnode, NULL))
		return;

	if (bfd && yang_dnode_exists(bfd, "./strict-hold-time"))
		return;

	vty_out(vty, " neighbor %s bfd strict\n", bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_bfd_strict_hold_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	bgp_bfd_enable(peer);
	event_cancel(&peer->bfd_config->t_hold_timer);
	peer->bfd_config->hold_time = yang_dnode_get_uint32(args->dnode, NULL);
	peer_flag_set(peer, PEER_FLAG_BFD_STRICT);
	bgp_nb_peer_bfd_apply(peer);
	return NB_OK;
}

int bgp_nb_peer_bfd_strict_hold_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !peer->bfd_config)
		return NB_OK;

	event_cancel(&peer->bfd_config->t_hold_timer);
	peer->bfd_config->hold_time = BFD_DEF_STRICT_HOLD_TIME;
	bgp_nb_peer_bfd_apply(peer);
	return NB_OK;
}

void bgp_nb_cli_show_peer_bfd_strict_hold(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults)
{
	vty_out(vty, " neighbor %s bfd strict hold-time %u\n", bgp_nb_config_peer_name(dnode),
		yang_dnode_get_uint32(dnode, NULL));
}

/*
 * peer_group_bind() deactivates any member AFI/SAFI the group does not have.
 * Bind is applied after neighbor AF enable (higher priority, so the group
 * exists), which clears an explicit "neighbor X activate". Put those back
 * from the candidate.
 */
static void bgp_nb_peer_reapply_enabled_af(struct peer *peer, const struct lyd_node *pg_leaf)
{
	const struct lyd_node *nbr, *container, *af;
	afi_t afi;
	safi_t safi;

	if (!peer || !pg_leaf)
		return;

	nbr = yang_dnode_get_parent(pg_leaf, "neighbor");
	if (!nbr)
		nbr = yang_dnode_get_parent(pg_leaf, "unnumbered-neighbor");
	if (!nbr)
		return;

	LY_LIST_FOR (lyd_child(nbr), container) {
		if (!strmatch(container->schema->name, "afi-safis"))
			continue;
		LY_LIST_FOR (lyd_child(container), af) {
			if (!strmatch(af->schema->name, "afi-safi"))
				continue;
			if (!yang_dnode_exists(af, "enabled") || !yang_dnode_get_bool(af, "enabled"))
				continue;
			if (!bgp_nb_dnode_afi_safi(af, &afi, &safi))
				continue;
			if (!peer->afc[afi][safi])
				peer_activate(peer, afi, safi);
		}
	}
}

int bgp_nb_neighbor_peer_group_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	struct peer_group *group;
	const char *group_name;
	as_t as;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
		peer = bgp_nb_config_peer(args->dnode);
		/*
		 * Soft lookup may return NULL (same-candidate create) or a
		 * stale/wrong entry without a live bgp — never deref blindly.
		 */
		if (!peer || !peer->bgp)
			return NB_OK;
		if (peer_dynamic_neighbor(peer)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "operation not allowed on a dynamic neighbor");
			return NB_ERR_VALIDATION;
		}
		group_name = yang_dnode_get_string(args->dnode, NULL);
		group = peer_group_lookup(peer->bgp, group_name);
		if (!group) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "Configure the peer-group first");
			return NB_ERR_VALIDATION;
		}
		/*
		 * Mirror peer_group_bind(): ebgp-multihop and ttl-security
		 * cannot be mixed across peer and group. APPLY alone returns
		 * a generic resource error; reject here so the CLI message
		 * matches classic behavior.
		 */
		if ((CHECK_FLAG(peer->flags, PEER_FLAG_EBGP_MULTIHOP) &&
		     group->conf->gtsm_hops != BGP_GTSM_HOPS_DISABLED) ||
		    (peer->gtsm_hops != BGP_GTSM_HOPS_DISABLED && group->conf->cfg_ttl != 0)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "%%Cannot configure both ttl-security hops and ebgp-multihop");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !peer->bgp)
		return NB_ERR_NOT_FOUND;

	group_name = yang_dnode_get_string(args->dnode, NULL);
	group = peer_group_lookup(peer->bgp, group_name);
	if (!group)
		return NB_ERR_NOT_FOUND;

	as = peer->as;
	ret = peer_group_bind(peer->bgp, &peer->connection->su, peer, group, &as);
	if (ret == BGP_ERR_NO_EBGP_MULTIHOP_WITH_TTLHACK) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   "%%Cannot configure both ttl-security hops and ebgp-multihop");
		return NB_ERR_VALIDATION;
	}
	if (ret != 0)
		return NB_ERR_RESOURCE;

	bgp_nb_peer_reapply_enabled_af(peer, args->dnode);

	if (group->conf->as_type != AS_UNSPECIFIED)
		bgp_nb_need_listening(peer->bgp);
	return NB_OK;
}

static bool bgp_nb_flag_inherited(uint64_t flags, uint64_t override, uint64_t flag)
{
	return CHECK_FLAG(flags, flag) && !CHECK_FLAG(override, flag);
}

static void bgp_nb_drop_session_flag(struct peer *peer, uint64_t flag)
{
	if (!bgp_nb_flag_inherited(peer->flags, peer->flags_override, flag))
		return;
	UNSET_FLAG(peer->flags_invert, flag);
	peer_flag_unset(peer, flag);
}

static void bgp_nb_drop_af_flag(struct peer *peer, afi_t afi, safi_t safi, uint64_t flag)
{
	if (!bgp_nb_flag_inherited(peer->af_flags[afi][safi], peer->af_flags_override[afi][safi],
				  flag))
		return;
	UNSET_FLAG(peer->af_flags_invert[afi][safi], flag);
	peer_af_flag_unset(peer, afi, safi, flag);
}

/* True when the neighbor YANG itself turned GR on or off. */
static bool bgp_nb_neighbor_gr_explicit(const struct lyd_node *nbr)
{
	if (!nbr)
		return false;
	if (yang_dnode_exists(nbr, "graceful-restart/enable") &&
	    yang_dnode_get_bool(nbr, "graceful-restart/enable"))
		return true;
	if (yang_dnode_exists(nbr, "graceful-restart/graceful-restart-helper") &&
	    yang_dnode_get_bool(nbr, "graceful-restart/graceful-restart-helper"))
		return true;
	if (yang_dnode_exists(nbr, "graceful-restart/graceful-restart-disable") &&
	    yang_dnode_get_bool(nbr, "graceful-restart/graceful-restart-disable"))
		return true;
	return false;
}

/*
 * Classic "no neighbor X peer-group" deletes the peer. YANG keeps the
 * neighbor, so after unbind drop every inherited value that is not an
 * explicit override. Unset helpers re-inherit while peer_group_active(),
 * so this runs only after peer_group_unbind().
 */
static void bgp_nb_neighbor_drop_inherited(struct peer *peer, const struct lyd_node *nbr)
{
	static const uint64_t session_flags[] = {
		PEER_FLAG_PASSIVE,
		PEER_FLAG_SHUTDOWN,
		PEER_FLAG_RTT_SHUTDOWN,
		PEER_FLAG_DONT_CAPABILITY,
		PEER_FLAG_OVERRIDE_CAPABILITY,
		PEER_FLAG_STRICT_CAP_MATCH,
		PEER_FLAG_DYNAMIC_CAPABILITY,
		PEER_FLAG_DISABLE_CONNECTED_CHECK,
		PEER_FLAG_CAPABILITY_ENHE,
		PEER_FLAG_ENFORCE_FIRST_AS,
		PEER_FLAG_IFPEER_V6ONLY,
		PEER_FLAG_DISABLE_LINK_BW_ENCODING_IEEE,
		PEER_FLAG_EXTENDED_OPT_PARAMS,
		PEER_FLAG_ROLE_STRICT_MODE,
		PEER_FLAG_LOCAL_AS_NO_PREPEND,
		PEER_FLAG_LOCAL_AS_REPLACE_AS,
		PEER_FLAG_DUAL_AS,
		PEER_FLAG_AIGP,
		PEER_FLAG_GRACEFUL_SHUTDOWN,
		PEER_FLAG_CAPABILITY_SOFT_VERSION_OLD,
		PEER_FLAG_CAPABILITY_SOFT_VERSION_NEW,
		PEER_FLAG_CAPABILITY_FQDN,
		PEER_FLAG_AS_LOOP_DETECTION,
		PEER_FLAG_EXTENDED_LINK_BANDWIDTH,
		PEER_FLAG_LONESOUL,
		PEER_FLAG_CAPABILITY_LINK_LOCAL,
		PEER_FLAG_BFD_STRICT,
		PEER_FLAG_RPKI_STRICT,
		PEER_FLAG_SEND_NHC_ATTRIBUTE,
		PEER_FLAG_IP_TRANSPARENT,
	};
	static const uint64_t af_flags[] = {
		PEER_FLAG_SEND_COMMUNITY,
		PEER_FLAG_SEND_EXT_COMMUNITY,
		PEER_FLAG_SEND_LARGE_COMMUNITY,
		PEER_FLAG_NEXTHOP_SELF,
		PEER_FLAG_REFLECTOR_CLIENT,
		PEER_FLAG_RSERVER_CLIENT,
		PEER_FLAG_SOFT_RECONFIG,
		PEER_FLAG_AS_PATH_UNCHANGED,
		PEER_FLAG_NEXTHOP_UNCHANGED,
		PEER_FLAG_MED_UNCHANGED,
		PEER_FLAG_REMOVE_PRIVATE_AS,
		PEER_FLAG_ORF_PREFIX_SM,
		PEER_FLAG_ORF_PREFIX_RM,
		PEER_FLAG_NEXTHOP_LOCAL_UNCHANGED,
		PEER_FLAG_FORCE_NEXTHOP_SELF,
		PEER_FLAG_REMOVE_PRIVATE_AS_ALL,
		PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE,
		PEER_FLAG_AS_OVERRIDE,
		PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE,
		PEER_FLAG_DISABLE_ADDPATH_RX,
		PEER_FLAG_ACCEPT_OWN,
		PEER_FLAG_SEND_EXT_COMMUNITY_RPKI,
		PEER_FLAG_ADDPATH_RX_PATHS_LIMIT,
		PEER_FLAG_CONFIG_ENCAPSULATION_SRV6,
		PEER_FLAG_CONFIG_ENCAPSULATION_SRV6_RELAX,
		PEER_FLAG_CONFIG_ENCAPSULATION_MPLS,
		PEER_FLAG_UPA,
	};
	afi_t afi;
	safi_t safi;
	unsigned int i;

	if (bgp_nb_flag_inherited(peer->flags, peer->flags_override, PEER_FLAG_PASSWORD)) {
		UNSET_FLAG(peer->flags_invert, PEER_FLAG_PASSWORD);
		peer_password_unset(peer);
	}
	if (bgp_nb_flag_inherited(peer->flags, peer->flags_override, PEER_FLAG_UPDATE_SOURCE)) {
		UNSET_FLAG(peer->flags_invert, PEER_FLAG_UPDATE_SOURCE);
		peer_update_source_unset(peer);
	}
	if (bgp_nb_flag_inherited(peer->flags, peer->flags_override, PEER_FLAG_TIMER)) {
		UNSET_FLAG(peer->flags_invert, PEER_FLAG_TIMER);
		peer_timers_unset(peer);
	}
	if (bgp_nb_flag_inherited(peer->flags, peer->flags_override, PEER_FLAG_TIMER_CONNECT)) {
		UNSET_FLAG(peer->flags_invert, PEER_FLAG_TIMER_CONNECT);
		peer_timers_connect_unset(peer);
	}
	if (bgp_nb_flag_inherited(peer->flags, peer->flags_override, PEER_FLAG_TIMER_DELAYOPEN)) {
		UNSET_FLAG(peer->flags_invert, PEER_FLAG_TIMER_DELAYOPEN);
		peer_timers_delayopen_unset(peer);
	}
	if (bgp_nb_flag_inherited(peer->flags, peer->flags_override, PEER_FLAG_ROUTEADV)) {
		UNSET_FLAG(peer->flags_invert, PEER_FLAG_ROUTEADV);
		peer_advertise_interval_unset(peer);
	}
	if (bgp_nb_flag_inherited(peer->flags, peer->flags_override, PEER_FLAG_LOCAL_AS)) {
		UNSET_FLAG(peer->flags_invert,
			   PEER_FLAG_LOCAL_AS | PEER_FLAG_LOCAL_AS_NO_PREPEND |
				   PEER_FLAG_LOCAL_AS_REPLACE_AS | PEER_FLAG_DUAL_AS);
		peer_local_as_unset(peer);
	}
	if (bgp_nb_flag_inherited(peer->flags, peer->flags_override, PEER_FLAG_TCP_MSS)) {
		UNSET_FLAG(peer->flags_invert, PEER_FLAG_TCP_MSS);
		peer_tcp_mss_unset(peer);
	}
	if (bgp_nb_flag_inherited(peer->flags, peer->flags_override, PEER_FLAG_ROLE)) {
		UNSET_FLAG(peer->flags_invert, PEER_FLAG_ROLE | PEER_FLAG_ROLE_STRICT_MODE);
		peer_role_unset(peer);
		peer->local_role = 0;
	}
	if (bgp_nb_flag_inherited(peer->flags, peer->flags_override, PEER_FLAG_PORT)) {
		UNSET_FLAG(peer->flags_invert, PEER_FLAG_PORT);
		peer_port_unset(peer);
	}
	if (!CHECK_FLAG(peer->flags_override, PEER_FLAG_EBGP_MULTIHOP) &&
	    (peer->cfg_ttl || CHECK_FLAG(peer->flags, PEER_FLAG_EBGP_MULTIHOP)))
		peer_cfg_ttl_set(peer, 0);
	if (peer->gtsm_hops != BGP_GTSM_HOPS_DISABLED &&
	    !(nbr && yang_dnode_exists(nbr, "ttl-security")))
		peer_ttl_security_hops_unset(peer);

	for (i = 0; i < array_size(session_flags); i++)
		bgp_nb_drop_session_flag(peer, session_flags[i]);

	FOREACH_AFI_SAFI (afi, safi) {
		const char *ident = yang_afi_safi_value2identity(afi, safi);
		struct bgp_filter *filter = &peer->filter[afi][safi];
		uint8_t *ov_in = &peer->filter_override[afi][safi][FILTER_IN];
		uint8_t *ov_out = &peer->filter_override[afi][safi][FILTER_OUT];
		const struct lyd_node *enabled = NULL;
		const struct lyd_node *addpath = NULL;
		const char *addpath_type = NULL;
		bool explicit_af = false;
		bool af_on = false;

		for (i = 0; i < array_size(af_flags); i++)
			bgp_nb_drop_af_flag(peer, afi, safi, af_flags[i]);

		if (bgp_nb_flag_inherited(peer->af_flags[afi][safi], peer->af_flags_override[afi][safi],
					  PEER_FLAG_MAX_PREFIX)) {
			UNSET_FLAG(peer->af_flags_invert[afi][safi], PEER_FLAG_MAX_PREFIX);
			peer_maximum_prefix_unset(peer, afi, safi);
		}
		if (bgp_nb_flag_inherited(peer->af_flags[afi][safi], peer->af_flags_override[afi][safi],
					  PEER_FLAG_MAX_PREFIX_OUT)) {
			UNSET_FLAG(peer->af_flags_invert[afi][safi], PEER_FLAG_MAX_PREFIX_OUT);
			peer_maximum_prefix_out_unset(peer, afi, safi);
		}
		if (bgp_nb_flag_inherited(peer->af_flags[afi][safi], peer->af_flags_override[afi][safi],
					  PEER_FLAG_ALLOWAS_IN)) {
			UNSET_FLAG(peer->af_flags_invert[afi][safi],
				   PEER_FLAG_ALLOWAS_IN | PEER_FLAG_ALLOWAS_IN_ORIGIN);
			peer_allowas_in_unset(peer, afi, safi);
		}
		if (bgp_nb_flag_inherited(peer->af_flags[afi][safi], peer->af_flags_override[afi][safi],
					  PEER_FLAG_WEIGHT)) {
			UNSET_FLAG(peer->af_flags_invert[afi][safi], PEER_FLAG_WEIGHT);
			peer_weight_unset(peer, afi, safi);
		}
		if (bgp_nb_flag_inherited(peer->af_flags[afi][safi], peer->af_flags_override[afi][safi],
					  PEER_FLAG_DEFAULT_ORIGINATE)) {
			UNSET_FLAG(peer->af_flags_invert[afi][safi], PEER_FLAG_DEFAULT_ORIGINATE);
			peer_default_originate_unset(peer, afi, safi);
		}
		if (!CHECK_FLAG(peer->af_flags_override[afi][safi], PEER_FLAG_SOO) && peer->soo[afi][safi]) {
			ecommunity_free(&peer->soo[afi][safi]);
			bgp_nb_drop_af_flag(peer, afi, safi, PEER_FLAG_SOO);
		}

		if (!CHECK_FLAG(*ov_in, PEER_FT_DISTRIBUTE_LIST) && filter->dlist[FILTER_IN].name)
			peer_distribute_unset(peer, afi, safi, FILTER_IN);
		if (!CHECK_FLAG(*ov_out, PEER_FT_DISTRIBUTE_LIST) && filter->dlist[FILTER_OUT].name)
			peer_distribute_unset(peer, afi, safi, FILTER_OUT);
		if (!CHECK_FLAG(*ov_in, PEER_FT_PREFIX_LIST) && filter->plist[FILTER_IN].name)
			peer_prefix_list_unset(peer, afi, safi, FILTER_IN);
		if (!CHECK_FLAG(*ov_out, PEER_FT_PREFIX_LIST) && filter->plist[FILTER_OUT].name)
			peer_prefix_list_unset(peer, afi, safi, FILTER_OUT);
		if (!CHECK_FLAG(*ov_in, PEER_FT_FILTER_LIST) && filter->aslist[FILTER_IN].name)
			peer_aslist_unset(peer, afi, safi, FILTER_IN);
		if (!CHECK_FLAG(*ov_out, PEER_FT_FILTER_LIST) && filter->aslist[FILTER_OUT].name)
			peer_aslist_unset(peer, afi, safi, FILTER_OUT);
		if (!CHECK_FLAG(*ov_in, PEER_FT_ROUTE_MAP) && filter->map[RMAP_IN].name)
			peer_route_map_unset(peer, afi, safi, RMAP_IN);
		if (!CHECK_FLAG(*ov_out, PEER_FT_ROUTE_MAP) && filter->map[RMAP_OUT].name)
			peer_route_map_unset(peer, afi, safi, RMAP_OUT);
		if (!CHECK_FLAG(peer->filter_override[afi][safi][0], PEER_FT_UNSUPPRESS_MAP) &&
		    filter->usmap.name)
			peer_unsuppress_map_unset(peer, afi, safi);
		if (!CHECK_FLAG(*ov_out, PEER_FT_ADVERTISE_MAP) && filter->advmap.aname)
			peer_advertise_map_unset(peer, afi, safi, filter->advmap.aname,
						 filter->advmap.amap, filter->advmap.cname,
						 filter->advmap.cmap, filter->advmap.condition);

		if (ident && nbr) {
			enabled = yang_dnode_getf(nbr,
						  "afi-safis/afi-safi[afi-safi-name='%s']/enabled",
						  ident);
			addpath = yang_dnode_getf(
				nbr, "afi-safis/afi-safi[afi-safi-name='%s']/add-paths/path-type",
				ident);
		}
		if (enabled) {
			explicit_af = true;
			af_on = yang_dnode_get_bool(enabled, NULL);
		}
		if (explicit_af) {
			if (af_on && !peer->afc[afi][safi])
				peer_activate(peer, afi, safi);
			else if (!af_on && peer->afc[afi][safi])
				peer_deactivate(peer, afi, safi);
		} else if (peer->bgp->default_af[afi][safi]) {
			if (!peer->afc[afi][safi])
				peer_activate(peer, afi, safi);
		} else if (peer->afc[afi][safi]) {
			peer_deactivate(peer, afi, safi);
		}

		if (addpath)
			addpath_type = yang_dnode_get_string(addpath, NULL);
		if (peer->addpath_type[afi][safi] != BGP_ADDPATH_NONE &&
		    (!addpath_type || strmatch(addpath_type, "none")))
			bgp_addpath_set_peer_type(peer, afi, safi, BGP_ADDPATH_NONE, 0);
	}

	/* Remote-as after AF flags so iBGP-only unsets still see the group AS. */
	if (!CHECK_FLAG(peer->flags_override, PEER_FLAG_REMOTE_AS)) {
		if (nbr && yang_dnode_exists(nbr, "neighbor-remote-as/remote-as-type"))
			SET_FLAG(peer->flags_override, PEER_FLAG_REMOTE_AS);
		else
			peer_as_change(peer, 0, AS_UNSPECIFIED, NULL);
	}

	if (!bgp_nb_neighbor_gr_explicit(nbr))
		bgp_peer_move_to_gr_mode(peer, PEER_GLOBAL_INHERIT);

	if (peer->bfd_config && !(nbr && yang_dnode_exists(nbr, "bfd-options/enable") &&
				  yang_dnode_get_bool(nbr, "bfd-options/enable")))
		bgp_peer_remove_bfd_config(peer);
}

int bgp_nb_neighbor_peer_group_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	const struct lyd_node *nbr;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !peer->group)
		return NB_OK;

	if (peer_group_unbind(peer->bgp, peer, peer->group) != 0)
		return NB_ERR_RESOURCE;

	nbr = yang_dnode_get_parent(args->dnode, "neighbor");
	if (!nbr)
		nbr = yang_dnode_get_parent(args->dnode, "unnumbered-neighbor");
	bgp_nb_neighbor_drop_inherited(peer, nbr);

	FOREACH_AFI_SAFI (afi, safi) {
		struct peer_af *paf = peer_af_find(peer, afi, safi);

		if (paf)
			update_group_adjust_peer(paf);
	}
	return NB_OK;
}

void bgp_nb_cli_show_neighbor_peer_group(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults)
{
	vty_out(vty, " neighbor %s peer-group %s\n", bgp_nb_config_peer_name(dnode),
		yang_dnode_get_string(dnode, NULL));
}

int bgp_nb_neighbor_local_port_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	peer_port_set(peer, yang_dnode_get_uint16(args->dnode, NULL));
	return NB_OK;
}

int bgp_nb_neighbor_local_port_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (peer)
		peer_port_unset(peer);
	return NB_OK;
}

void bgp_nb_cli_show_neighbor_local_port(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults)
{
	uint16_t port = yang_dnode_get_uint16(dnode, NULL);

	if (port == BGP_PORT_DEFAULT && !show_defaults)
		return;

	vty_out(vty, " neighbor %s port %u\n", bgp_nb_config_peer_name(dnode), port);
}

int bgp_nb_neighbor_local_interface_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
		peer = bgp_nb_config_peer(args->dnode);
		if (peer && peer->conf_if) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "interface not valid for unnumbered peer");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	peer_interface_set(peer, yang_dnode_get_string(args->dnode, NULL));
	return NB_OK;
}

int bgp_nb_neighbor_local_interface_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (peer)
		peer_interface_unset(peer);
	return NB_OK;
}

void bgp_nb_cli_show_neighbor_local_interface(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults)
{
	vty_out(vty, " neighbor %s interface %s\n", bgp_nb_config_peer_name(dnode),
		yang_dnode_get_string(dnode, NULL));
}

/*
 * Neighbor AFI/SAFI helpers and callbacks
 */
static bool bgp_nb_dnode_afi_safi(const struct lyd_node *dnode, afi_t *afi, safi_t *safi)
{
	const struct lyd_node *af;
	const char *name;

	af = yang_dnode_get_parent(dnode, "afi-safi");
	if (!af)
		return false;

	name = yang_dnode_get_string(af, "./afi-safi-name");
	yang_afi_safi_identity2value(name, afi, safi);
	return true;
}

/*
 * Global AFI/SAFI + network-config
 */
int bgp_nb_global_afi_safi_create(struct nb_cb_create_args *args)
{
	return NB_OK;
}

int bgp_nb_global_afi_safi_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

static const char *bgp_nb_afi_safi_cli_name(afi_t afi, safi_t safi)
{
	if (afi == AFI_IP) {
		if (safi == SAFI_UNICAST)
			return "ipv4 unicast";
		if (safi == SAFI_LABELED_UNICAST)
			return "ipv4 labeled-unicast";
		if (safi == SAFI_MULTICAST)
			return "ipv4 multicast";
		if (safi == SAFI_MPLS_VPN)
			return "ipv4 vpn";
		if (safi == SAFI_ENCAP)
			return "ipv4 encap";
		if (safi == SAFI_FLOWSPEC)
			return "ipv4 flowspec";
		if (safi == SAFI_UNREACH)
			return "ipv4 unreachability";
	} else if (afi == AFI_IP6) {
		if (safi == SAFI_UNICAST)
			return "ipv6 unicast";
		if (safi == SAFI_LABELED_UNICAST)
			return "ipv6 labeled-unicast";
		if (safi == SAFI_MULTICAST)
			return "ipv6 multicast";
		if (safi == SAFI_MPLS_VPN)
			return "ipv6 vpn";
		if (safi == SAFI_ENCAP)
			return "ipv6 encap";
		if (safi == SAFI_FLOWSPEC)
			return "ipv6 flowspec";
		if (safi == SAFI_UNREACH)
			return "ipv6 unreachability";
	} else if (afi == AFI_L2VPN && safi == SAFI_EVPN) {
		return "l2vpn evpn";
	} else if (afi == AFI_BGP_LS && safi == SAFI_BGP_LS) {
		return "link-state link-state";
	}
	return NULL;
}

void bgp_nb_cli_show_global_afi_safi(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults)
{
	afi_t afi;
	safi_t safi;
	const char *afname;
	const char *ident;

	ident = yang_dnode_get_string(dnode, "afi-safi-name");
	yang_afi_safi_identity2value(ident, &afi, &safi);
	afname = bgp_nb_afi_safi_cli_name(afi, safi);
	if (!afname)
		return;

	/* vty_frame: header only emitted if a child prints config. */
	vty_frame(vty, " !\n address-family %s\n", afname);
}

void bgp_nb_cli_show_global_afi_safi_end(struct vty *vty, const struct lyd_node *dnode)
{
	const struct lyd_node *bgp_dnode;
	const struct lyd_node *container;
	const struct lyd_node *peer;
	const struct lyd_node *af;
	const char *ident;

	ident = yang_dnode_get_string(dnode, "afi-safi-name");
	bgp_dnode = yang_dnode_get_parent(dnode, "bgp");

	/*
	 * Peer / peer-group AF knobs live under neighbors|peer-groups in
	 * YANG but must appear inside the address-family block in CLI.
	 */
	if (bgp_dnode) {
		container = yang_dnode_get(bgp_dnode, "neighbors");
		if (container) {
			LY_LIST_FOR (lyd_child(container), peer) {
				if (!strmatch(peer->schema->name, "neighbor") &&
				    !strmatch(peer->schema->name, "unnumbered-neighbor"))
					continue;
				af = yang_dnode_getf(peer, "afi-safis/afi-safi[afi-safi-name='%s']",
						     ident);
				if (af)
					nb_cli_show_dnode_cmds(vty, af, false);
			}
		}

		container = yang_dnode_get(bgp_dnode, "peer-groups");
		if (container) {
			LY_LIST_FOR (lyd_child(container), peer) {
				if (!strmatch(peer->schema->name, "peer-group"))
					continue;
				af = yang_dnode_getf(peer, "afi-safis/afi-safi[afi-safi-name='%s']",
						     ident);
				if (af)
					nb_cli_show_dnode_cmds(vty, af, false);
			}
		}
	}

	vty_endframe(vty, " exit-address-family\n");
}

static int bgp_nb_network_apply(const struct lyd_node *dnode, bool clear_rmap)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	const char *prefix;
	const char *rmap = NULL;
	bool backdoor = false;
	uint32_t label_index = BGP_INVALID_LABEL_INDEX;
	struct prefix p;
	struct bgp_dest *dest;
	struct bgp_static *bgp_static;
	char err[256];

	bgp = nb_running_get_entry(dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	prefix = yang_dnode_get_string(dnode, "./prefix");
	if (yang_dnode_exists(dnode, "./backdoor"))
		backdoor = yang_dnode_get_bool(dnode, "./backdoor");
	/*
	 * Destroy callbacks are handed the running-tree node, so the leaf
	 * being deleted is still visible. clear_rmap forces it absent.
	 */
	if (!clear_rmap && yang_dnode_exists(dnode, "./rmap-policy-export"))
		rmap = yang_dnode_get_string(dnode, "./rmap-policy-export");
	if (yang_dnode_exists(dnode, "./label-index"))
		label_index = yang_dnode_get_uint32(dnode, "./label-index");
	else if (str2prefix(prefix, &p)) {
		/* label-index is immutable once set; preserve existing. */
		apply_mask(&p);
		dest = bgp_node_lookup(bgp->static_routes[afi][safi], &p);
		if (dest) {
			bgp_static = bgp_dest_get_bgp_static_info(dest);
			if (bgp_static)
				label_index = bgp_static->label_index;
			bgp_dest_unlock_node(dest);
		}
	}

	if (bgp_network_set(bgp, afi, safi, prefix, rmap, backdoor ? 1 : 0, label_index, err,
			    sizeof(err)) < 0)
		return NB_ERR_RESOURCE;
	return NB_OK;
}

int bgp_nb_network_create(struct nb_cb_create_args *args)
{
	if (args->event == NB_EV_VALIDATE) {
		struct prefix p;
		const char *prefix = yang_dnode_get_string(args->dnode, "./prefix");

		if (!str2prefix(prefix, &p)) {
			snprintfrr(args->errmsg, args->errmsg_len, "Malformed network prefix");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	return bgp_nb_network_apply(args->dnode, false);
}

int bgp_nb_network_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	const char *prefix;
	char err[256];

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	prefix = yang_dnode_get_string(args->dnode, "./prefix");
	if (bgp_network_unset(bgp, afi, safi, prefix, NULL, BGP_INVALID_LABEL_INDEX, err,
			      sizeof(err)) < 0)
		return NB_OK; /* already gone */
	return NB_OK;
}

void bgp_nb_cli_show_network(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, "  network %s", yang_dnode_get_string(dnode, "./prefix"));
	if (yang_dnode_exists(dnode, "./label-index"))
		vty_out(vty, " label-index %u", yang_dnode_get_uint32(dnode, "./label-index"));
	if (yang_dnode_exists(dnode, "./rmap-policy-export"))
		vty_out(vty, " route-map %s", yang_dnode_get_string(dnode, "./rmap-policy-export"));
	if (yang_dnode_exists(dnode, "./backdoor") && yang_dnode_get_bool(dnode, "./backdoor"))
		vty_out(vty, " backdoor");
	vty_out(vty, "\n");
}

int bgp_nb_network_backdoor_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_network_apply(yang_dnode_get_parent(args->dnode, "network-config"), false);
}

int bgp_nb_network_label_index_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_network_apply(yang_dnode_get_parent(args->dnode, "network-config"), false);
}

int bgp_nb_network_label_index_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_network_apply(yang_dnode_get_parent(args->dnode, "network-config"), false);
}

int bgp_nb_network_rmap_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_network_apply(yang_dnode_get_parent(args->dnode, "network-config"), false);
}

int bgp_nb_network_rmap_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_network_apply(yang_dnode_get_parent(args->dnode, "network-config"), true);
}

/*
 * L3VPN network-config[rd]/prefix-list[prefix] — YANG "label-index" stores
 * the MPLS VPN label (classic CLI "label|tag").
 */
static int bgp_nb_vpn_network_apply(const struct lyd_node *prefix_dnode)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	const struct lyd_node *rd_dnode;
	const char *rd_str;
	const char *prefix;
	const char *rmap = NULL;
	char label_buf[16];
	char err[256];

	rd_dnode = yang_dnode_get_parent(prefix_dnode, "network-config");
	if (!rd_dnode)
		return NB_ERR_NOT_FOUND;

	bgp = nb_running_get_entry(rd_dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(rd_dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	rd_str = yang_dnode_get_string(rd_dnode, "./rd");
	prefix = yang_dnode_get_string(prefix_dnode, "./prefix");
	if (!yang_dnode_exists(prefix_dnode, "./label-index"))
		return NB_ERR_VALIDATION;

	snprintfrr(label_buf, sizeof(label_buf), "%u",
		   yang_dnode_get_uint32(prefix_dnode, "./label-index"));
	if (yang_dnode_exists(prefix_dnode, "./rmap-policy-export"))
		rmap = yang_dnode_get_string(prefix_dnode, "./rmap-policy-export");

	if (bgp_vpn_network_set(bgp, false, prefix, rd_str, label_buf, afi, rmap, err,
				sizeof(err)) < 0)
		return NB_ERR_RESOURCE;
	return NB_OK;
}

int bgp_nb_vpn_network_rd_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	struct prefix_rd prd;
	const struct lyd_node *af;

	if (args->event == NB_EV_VALIDATE) {
		if (!str2prefix_rd(yang_dnode_get_string(args->dnode, "./rd"), &prd)) {
			snprintfrr(args->errmsg, args->errmsg_len, "Malformed Route Distinguisher");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	af = yang_dnode_get_parent(args->dnode, "afi-safi");
	bgp = nb_running_get_entry(af ? af : args->dnode, NULL, true);
	if (!bgp)
		return NB_ERR_NOT_FOUND;

	nb_running_set_entry(args->dnode, bgp);
	return NB_OK;
}

int bgp_nb_vpn_network_rd_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Prefix children are destroyed first and withdraw routes. */
	nb_running_unset_entry(args->dnode);
	return NB_OK;
}

int bgp_nb_vpn_network_prefix_create(struct nb_cb_create_args *args)
{
	struct prefix p;

	if (args->event == NB_EV_VALIDATE) {
		if (!str2prefix(yang_dnode_get_string(args->dnode, "./prefix"), &p)) {
			snprintfrr(args->errmsg, args->errmsg_len, "Malformed network prefix");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* label-index is mandatory; may be applied in same changeset. */
	if (!yang_dnode_exists(args->dnode, "./label-index"))
		return NB_OK;
	return bgp_nb_vpn_network_apply(args->dnode);
}

int bgp_nb_vpn_network_prefix_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	const struct lyd_node *rd_dnode;
	const char *rd_str;
	const char *prefix;
	char err[256];

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rd_dnode = yang_dnode_get_parent(args->dnode, "network-config");
	if (!rd_dnode)
		return NB_OK;

	bgp = nb_running_get_entry(rd_dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(rd_dnode, &afi, &safi))
		return NB_OK;

	rd_str = yang_dnode_get_string(rd_dnode, "./rd");
	prefix = yang_dnode_get_string(args->dnode, "./prefix");
	bgp_vpn_network_set(bgp, true, prefix, rd_str, NULL, afi, NULL, err, sizeof(err));
	return NB_OK;
}

void bgp_nb_cli_show_vpn_network_prefix(struct vty *vty, const struct lyd_node *dnode,
					bool show_defaults)
{
	const struct lyd_node *rd_dnode;

	rd_dnode = yang_dnode_get_parent(dnode, "network-config");
	if (!rd_dnode)
		return;

	vty_out(vty, "  network %s rd %s label %u", yang_dnode_get_string(dnode, "./prefix"),
		yang_dnode_get_string(rd_dnode, "./rd"),
		yang_dnode_get_uint32(dnode, "./label-index"));
	if (yang_dnode_exists(dnode, "./rmap-policy-export"))
		vty_out(vty, " route-map %s", yang_dnode_get_string(dnode, "./rmap-policy-export"));
	vty_out(vty, "\n");
}

int bgp_nb_vpn_network_label_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_vpn_network_apply(yang_dnode_get_parent(args->dnode, "prefix-list"));
}

int bgp_nb_vpn_network_rmap_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_vpn_network_apply(yang_dnode_get_parent(args->dnode, "prefix-list"));
}

static const struct lyd_node *bgp_nb_candidate_match(const struct lyd_node *old);

int bgp_nb_vpn_network_rmap_destroy(struct nb_cb_destroy_args *args)
{
	const struct lyd_node *pfx;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/*
	 * The running tree still has the route-map being deleted. Rebuild
	 * from the candidate so the withdrawn leaf is not applied again.
	 * A missing prefix means the network itself is going away; its
	 * destroy withdraws the route.
	 */
	pfx = bgp_nb_candidate_match(yang_dnode_get_parent(args->dnode, "prefix-list"));
	if (!pfx)
		return NB_OK;
	return bgp_nb_vpn_network_apply(pfx);
}

/*
 * Aggregate-address
 */
#define AGGREGATE_AS_SET_NB   1
#define AGGREGATE_AS_UNSET_NB 0

static uint8_t bgp_nb_aggregate_origin_from_str(const char *s)
{
	if (!s || strmatch(s, "unspecified"))
		return BGP_ORIGIN_UNSPECIFIED;
	if (strmatch(s, "igp"))
		return BGP_ORIGIN_IGP;
	if (strmatch(s, "egp"))
		return BGP_ORIGIN_EGP;
	if (strmatch(s, "incomplete"))
		return BGP_ORIGIN_INCOMPLETE;
	return BGP_ORIGIN_UNSPECIFIED;
}

static int bgp_nb_aggregate_apply(const struct lyd_node *dnode)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	const char *prefix;
	const char *rmap = NULL;
	const char *suppress = NULL;
	uint8_t summary_only = 0;
	uint8_t as_set = AGGREGATE_AS_UNSET_NB;
	uint8_t origin = BGP_ORIGIN_UNSPECIFIED;
	bool match_med = false;
	bool upa = false;
	bool upa_drop = false;
	uint32_t upa_max = 0;
	char err[256];

	bgp = nb_running_get_entry(dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	prefix = yang_dnode_get_string(dnode, "./prefix");
	if (yang_dnode_exists(dnode, "./summary-only") &&
	    yang_dnode_get_bool(dnode, "./summary-only"))
		summary_only = 1;
	if (yang_dnode_exists(dnode, "./as-set") && yang_dnode_get_bool(dnode, "./as-set"))
		as_set = AGGREGATE_AS_SET_NB;
	if (yang_dnode_exists(dnode, "./match-med") && yang_dnode_get_bool(dnode, "./match-med"))
		match_med = true;
	if (yang_dnode_exists(dnode, "./origin"))
		origin = bgp_nb_aggregate_origin_from_str(yang_dnode_get_string(dnode, "./origin"));
	if (yang_dnode_exists(dnode, "./rmap-policy-export"))
		rmap = yang_dnode_get_string(dnode, "./rmap-policy-export");
	if (yang_dnode_exists(dnode, "./suppress-map"))
		suppress = yang_dnode_get_string(dnode, "./suppress-map");
	if (yang_dnode_exists(dnode, "./upa") && yang_dnode_get_bool(dnode, "./upa"))
		upa = true;
	if (yang_dnode_exists(dnode, "./upa-drop") && yang_dnode_get_bool(dnode, "./upa-drop")) {
		upa_drop = true;
		upa = true;
	}
	if (yang_dnode_exists(dnode, "./upa-max-routes")) {
		upa_max = yang_dnode_get_uint16(dnode, "./upa-max-routes");
		upa = true;
	}

	if (bgp_aggregate_config_set(bgp, prefix, afi, safi, rmap, summary_only, as_set, origin,
				     match_med, suppress, upa, upa_drop, upa_max, err,
				     sizeof(err)) != 0)
		return NB_ERR_RESOURCE;
	return NB_OK;
}

int bgp_nb_aggregate_create(struct nb_cb_create_args *args)
{
	if (args->event == NB_EV_VALIDATE) {
		struct prefix p;
		const char *prefix = yang_dnode_get_string(args->dnode, "./prefix");

		if (!str2prefix(prefix, &p)) {
			snprintfrr(args->errmsg, args->errmsg_len, "Malformed aggregate prefix");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_aggregate_apply(args->dnode);
}

int bgp_nb_aggregate_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	const char *prefix;
	char err[256];

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	prefix = yang_dnode_get_string(args->dnode, "./prefix");
	bgp_aggregate_config_unset(bgp, prefix, afi, safi, err, sizeof(err));
	return NB_OK;
}

void bgp_nb_cli_show_aggregate(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const char *origin;

	vty_out(vty, "  aggregate-address %s", yang_dnode_get_string(dnode, "./prefix"));
	if (yang_dnode_exists(dnode, "./as-set") && yang_dnode_get_bool(dnode, "./as-set"))
		vty_out(vty, " as-set");
	if (yang_dnode_exists(dnode, "./summary-only") &&
	    yang_dnode_get_bool(dnode, "./summary-only"))
		vty_out(vty, " summary-only");
	if (yang_dnode_exists(dnode, "./rmap-policy-export"))
		vty_out(vty, " route-map %s", yang_dnode_get_string(dnode, "./rmap-policy-export"));
	if (yang_dnode_exists(dnode, "./origin")) {
		origin = yang_dnode_get_string(dnode, "./origin");
		if (!strmatch(origin, "unspecified"))
			vty_out(vty, " origin %s", origin);
	}
	if (yang_dnode_exists(dnode, "./match-med") && yang_dnode_get_bool(dnode, "./match-med"))
		vty_out(vty, " matching-MED-only");
	if (yang_dnode_exists(dnode, "./suppress-map"))
		vty_out(vty, " suppress-map %s", yang_dnode_get_string(dnode, "./suppress-map"));
	if ((yang_dnode_exists(dnode, "./upa") && yang_dnode_get_bool(dnode, "./upa")) ||
	    (yang_dnode_exists(dnode, "./upa-drop") && yang_dnode_get_bool(dnode, "./upa-drop")) ||
	    yang_dnode_exists(dnode, "./upa-max-routes")) {
		vty_out(vty, " upa");
		if (yang_dnode_exists(dnode, "./upa-drop") &&
		    yang_dnode_get_bool(dnode, "./upa-drop"))
			vty_out(vty, " drop");
		if (yang_dnode_exists(dnode, "./upa-max-routes"))
			vty_out(vty, " max-routes %u",
				yang_dnode_get_uint16(dnode, "./upa-max-routes"));
	}
	vty_out(vty, "\n");
}

int bgp_nb_aggregate_bool_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_aggregate_apply(yang_dnode_get_parent(args->dnode, "aggregate-route"));
}

int bgp_nb_aggregate_origin_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_aggregate_apply(yang_dnode_get_parent(args->dnode, "aggregate-route"));
}

int bgp_nb_aggregate_rmap_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_aggregate_apply(yang_dnode_get_parent(args->dnode, "aggregate-route"));
}

/*
 * Destroy callbacks are handed the running tree, so a deleted leaf is still
 * visible there. Return the same node from the transaction candidate, or
 * NULL when that node is being removed in this commit.
 */
static const struct lyd_node *bgp_nb_candidate_match(const struct lyd_node *old)
{
	const struct lyd_node *root;
	char path[XPATH_MAXLEN];

	if (!old)
		return NULL;

	root = nb_transaction_candidate_dnode();
	if (!root || !yang_dnode_get_path(old, path, sizeof(path)))
		return NULL;
	if (!yang_dnode_exists(root, path))
		return NULL;
	return yang_dnode_get(root, path);
}

int bgp_nb_aggregate_rmap_destroy(struct nb_cb_destroy_args *args)
{
	const struct lyd_node *agg;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/*
	 * Destroy runs on the running tree, which still contains the leaf
	 * this callback is removing. Apply the candidate aggregate so a
	 * deleted route-map, suppress-map, or upa-max is not put back.
	 */
	agg = bgp_nb_candidate_match(yang_dnode_get_parent(args->dnode, "aggregate-route"));
	if (!agg)
		return NB_OK;
	return bgp_nb_aggregate_apply(agg);
}

int bgp_nb_aggregate_suppress_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_aggregate_apply(yang_dnode_get_parent(args->dnode, "aggregate-route"));
}

int bgp_nb_aggregate_suppress_destroy(struct nb_cb_destroy_args *args)
{
	const struct lyd_node *agg;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	agg = bgp_nb_candidate_match(yang_dnode_get_parent(args->dnode, "aggregate-route"));
	if (!agg)
		return NB_OK;
	return bgp_nb_aggregate_apply(agg);
}

int bgp_nb_aggregate_upa_max_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_aggregate_apply(yang_dnode_get_parent(args->dnode, "aggregate-route"));
}

int bgp_nb_aggregate_upa_max_destroy(struct nb_cb_destroy_args *args)
{
	const struct lyd_node *agg;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	agg = bgp_nb_candidate_match(yang_dnode_get_parent(args->dnode, "aggregate-route"));
	if (!agg)
		return NB_OK;
	return bgp_nb_aggregate_apply(agg);
}

/*
 * maximum-paths
 */
static int bgp_nb_maxpaths_apply(const struct lyd_node *dnode, int peer_type, bool unset)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	uint16_t maxpaths = 0;
	bool same_clusterlen = false;
	const struct lyd_node *ibgp;
	int ret;

	bgp = nb_running_get_entry(dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	if (safi == SAFI_UNREACH)
		return NB_ERR_VALIDATION;

	if (unset) {
		if (bgp_maximum_paths_unset(bgp, afi, safi, peer_type) < 0)
			return NB_ERR_RESOURCE;
		bgp_recalculate_all_bestpaths(bgp);
		return NB_OK;
	}

	maxpaths = yang_dnode_get_uint16(dnode, NULL);
	if (maxpaths > multipath_num)
		return NB_ERR_VALIDATION;

	if (peer_type == BGP_PEER_IBGP) {
		ibgp = yang_dnode_get_parent(dnode, "ibgp");
		if (ibgp && yang_dnode_exists(ibgp, "./cluster-length-list") &&
		    yang_dnode_get_bool(ibgp, "./cluster-length-list"))
			same_clusterlen = true;
	}

	ret = bgp_maximum_paths_set(bgp, afi, safi, peer_type, maxpaths, same_clusterlen);
	if (ret < 0)
		return NB_ERR_RESOURCE;
	bgp_recalculate_all_bestpaths(bgp);
	return NB_OK;
}

int bgp_nb_maxpaths_ebgp_modify(struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_VALIDATE) {
		if (yang_dnode_get_uint16(args->dnode, NULL) > multipath_num) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "maximum-paths exceeds multipath-num %u", multipath_num);
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_maxpaths_apply(args->dnode, BGP_PEER_EBGP, false);
}

int bgp_nb_maxpaths_ebgp_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_maxpaths_apply(args->dnode, BGP_PEER_EBGP, true);
}

void bgp_nb_cli_show_maxpaths_ebgp(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults)
{
	uint16_t maxpaths = yang_dnode_get_uint16(dnode, NULL);

	if (maxpaths != multipath_num || show_defaults)
		vty_out(vty, "  maximum-paths %u\n", maxpaths);
}

int bgp_nb_maxpaths_ibgp_modify(struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_VALIDATE) {
		if (yang_dnode_get_uint16(args->dnode, NULL) > multipath_num) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "maximum-paths exceeds multipath-num %u", multipath_num);
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_maxpaths_apply(args->dnode, BGP_PEER_IBGP, false);
}

int bgp_nb_maxpaths_ibgp_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_maxpaths_apply(args->dnode, BGP_PEER_IBGP, true);
}

void bgp_nb_cli_show_maxpaths_ibgp(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults)
{
	const struct lyd_node *ibgp = yang_dnode_get_parent(dnode, "ibgp");
	uint16_t maxpaths = yang_dnode_get_uint16(dnode, NULL);
	bool cluster = ibgp && yang_dnode_exists(ibgp, "./cluster-length-list") &&
		       yang_dnode_get_bool(ibgp, "./cluster-length-list");

	if (maxpaths != multipath_num || cluster || show_defaults) {
		vty_out(vty, "  maximum-paths ibgp %u", maxpaths);
		if (cluster)
			vty_out(vty, " equal-cluster-length");
		vty_out(vty, "\n");
	}
}

int bgp_nb_maxpaths_ibgp_cluster_modify(struct nb_cb_modify_args *args)
{
	const struct lyd_node *ibgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ibgp = yang_dnode_get_parent(args->dnode, "ibgp");
	if (!ibgp || !yang_dnode_exists(ibgp, "./maximum-paths"))
		return NB_OK;

	return bgp_nb_maxpaths_apply(yang_dnode_get(ibgp, "./maximum-paths"), BGP_PEER_IBGP, false);
}

/*
 * redistribution-list (ipv4/ipv6 unicast)
 */
static int bgp_nb_redistribute_validate(struct bgp *bgp, afi_t afi, int type,
					unsigned short instance, char *errmsg, size_t errmsg_len)
{
	if (type == ZEBRA_ROUTE_BGP) {
		snprintfrr(errmsg, errmsg_len, "Redistributing BGP into BGP is not allowed");
		return NB_ERR_VALIDATION;
	}

	if (type == ZEBRA_ROUTE_TABLE || type == ZEBRA_ROUTE_TABLE_DIRECT) {
		if (instance == 0) {
			snprintfrr(errmsg, errmsg_len,
				   "table redistribution requires an instance/table id");
			return NB_ERR_VALIDATION;
		}
	}

	if (type == ZEBRA_ROUTE_TABLE_DIRECT) {
		if (instance == RT_TABLE_MAIN || instance == RT_TABLE_LOCAL) {
			snprintfrr(errmsg, errmsg_len,
				   "'table-direct' cannot use %u routing table", instance);
			return NB_ERR_VALIDATION;
		}
		if (afi == AFI_IP6 && bgp->vrf_id != VRF_DEFAULT) {
			snprintfrr(errmsg, errmsg_len,
				   "Only default BGP instance can use 'table-direct'");
			return NB_ERR_VALIDATION;
		}
	}

	return NB_OK;
}

static int bgp_nb_redistribute_apply(const struct lyd_node *dnode)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	int type;
	unsigned short instance;
	struct bgp_redist *red;
	bool changed = false;
	const char *rmap_name;
	struct route_map *route_map;

	bgp = nb_running_get_entry(dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	if (safi != SAFI_UNICAST)
		return NB_ERR_VALIDATION;

	type = yang_dnode_get_enum(dnode, "./route-type");
	instance = yang_dnode_get_uint16(dnode, "./route-instance");

	red = bgp_redist_add(bgp, afi, type, instance);
	if (!red)
		return NB_ERR_RESOURCE;

	if (yang_dnode_exists(dnode, "./metric")) {
		changed |= bgp_redistribute_metric_set(bgp, red, afi, type,
						       yang_dnode_get_uint32(dnode, "./metric"));
	} else {
		changed |= bgp_redistribute_metric_unset(bgp, red, afi, type);
	}

	if (yang_dnode_exists(dnode, "./rmap-policy-import")) {
		rmap_name = yang_dnode_get_string(dnode, "./rmap-policy-import");
		route_map = route_map_lookup_by_name(rmap_name);
		changed |= bgp_redistribute_rmap_set(red, rmap_name, route_map);
	} else {
		changed |= bgp_redistribute_rmap_unset(red);
	}

	bgp_redistribute_set(bgp, afi, type, instance, changed);
	return NB_OK;
}

int bgp_nb_redistribute_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	int type;
	unsigned short instance;

	if (args->event == NB_EV_VALIDATE) {
		bgp = nb_running_get_entry(args->dnode, NULL, false);
		if (!bgp)
			return NB_OK;
		if (!bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
			return NB_ERR_VALIDATION;
		type = yang_dnode_get_enum(args->dnode, "./route-type");
		instance = yang_dnode_get_uint16(args->dnode, "./route-instance");
		return bgp_nb_redistribute_validate(bgp, afi, type, instance, args->errmsg,
						    args->errmsg_len);
	}
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_redistribute_apply(args->dnode);
}

int bgp_nb_redistribute_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	int type;
	unsigned short instance;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	type = yang_dnode_get_enum(args->dnode, "./route-type");
	instance = yang_dnode_get_uint16(args->dnode, "./route-instance");
	bgp_redistribute_unset(bgp, afi, type, instance);
	return NB_OK;
}

void bgp_nb_cli_show_redistribute(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const char *type;
	uint16_t instance;

	type = yang_dnode_get_string(dnode, "./route-type");
	instance = yang_dnode_get_uint16(dnode, "./route-instance");

	vty_out(vty, "  redistribute %s", type);
	if (instance)
		vty_out(vty, " %u", instance);
	if (yang_dnode_exists(dnode, "./metric"))
		vty_out(vty, " metric %u", yang_dnode_get_uint32(dnode, "./metric"));
	if (yang_dnode_exists(dnode, "./rmap-policy-import"))
		vty_out(vty, " route-map %s", yang_dnode_get_string(dnode, "./rmap-policy-import"));
	vty_out(vty, "\n");
}

int bgp_nb_redistribute_metric_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_redistribute_apply(yang_dnode_get_parent(args->dnode, "redistribution-list"));
}


/*
 * Destroy callbacks see the running tree, where the deleted leaf is still
 * present. Re-applying the parent would restore it, so unset that leaf only.
 */
static int bgp_nb_redistribute_unset_leaf(const struct lyd_node *leaf, bool metric, bool rmap)
{
	const struct lyd_node *parent;
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	int type;
	unsigned short instance;
	struct bgp_redist *red;
	bool changed = false;

	parent = yang_dnode_get_parent(leaf, "redistribution-list");
	if (!parent)
		return NB_OK;

	bgp = nb_running_get_entry(parent, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(parent, &afi, &safi))
		return NB_OK;

	type = yang_dnode_get_enum(parent, "./route-type");
	instance = yang_dnode_get_uint16(parent, "./route-instance");
	red = bgp_redist_lookup(bgp, afi, type, instance);
	if (!red)
		return NB_OK;

	if (metric)
		changed |= bgp_redistribute_metric_unset(bgp, red, afi, type);
	if (rmap)
		changed |= bgp_redistribute_rmap_unset(red);
	if (changed)
		bgp_redistribute_set(bgp, afi, type, instance, true);
	return NB_OK;
}

int bgp_nb_redistribute_metric_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_redistribute_unset_leaf(args->dnode, true, false);
}

int bgp_nb_redistribute_rmap_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_redistribute_apply(yang_dnode_get_parent(args->dnode, "redistribution-list"));
}

int bgp_nb_redistribute_rmap_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_redistribute_unset_leaf(args->dnode, false, true);
}

/*
 * admin-distance / admin-distance-route (unicast + multicast)
 */
static int bgp_nb_distance_bgp_apply(const struct lyd_node *leaf)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	const struct lyd_node *admin;
	uint8_t ebgp, ibgp, local;

	admin = yang_dnode_get_parent(leaf, "admin-distance");
	if (!admin)
		return NB_ERR_NOT_FOUND;

	bgp = nb_running_get_entry(admin, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(admin, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	if (!yang_dnode_exists(admin, "./external") && !yang_dnode_exists(admin, "./internal") &&
	    !yang_dnode_exists(admin, "./local")) {
		bgp_distance_bgp_unset(bgp, afi, safi);
		return NB_OK;
	}

	ebgp = yang_dnode_exists(admin, "./external") ? yang_dnode_get_uint8(admin, "./external")
						      : ZEBRA_EBGP_DISTANCE_DEFAULT;
	ibgp = yang_dnode_exists(admin, "./internal") ? yang_dnode_get_uint8(admin, "./internal")
						      : ZEBRA_IBGP_DISTANCE_DEFAULT;
	local = yang_dnode_exists(admin, "./local") ? yang_dnode_get_uint8(admin, "./local")
						    : ZEBRA_IBGP_DISTANCE_DEFAULT;

	bgp_distance_bgp_set(bgp, afi, safi, ebgp, ibgp, local);
	return NB_OK;
}

int bgp_nb_distance_bgp_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_distance_bgp_apply(args->dnode);
}

int bgp_nb_distance_bgp_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_distance_bgp_apply(args->dnode);
}

void bgp_nb_cli_show_distance_bgp(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const struct lyd_node *admin = yang_dnode_get_parent(dnode, "admin-distance");
	const struct lyd_node *earlier;
	const char *leaf = dnode->schema->name;
	uint8_t ebgp, ibgp, local;

	if (!admin)
		return;

	/*
	 * external owns the line when nb_cli_show visits it. internal and local
	 * print only when every earlier distance leaf stays at its default, so
	 * "distance bgp 20 50 200" is not dropped.
	 */
	if (strmatch(leaf, "internal") || strmatch(leaf, "local")) {
		if (yang_dnode_exists(admin, "./external")) {
			earlier = yang_dnode_get(admin, "./external");
			if (show_defaults || !yang_dnode_is_default(earlier, NULL))
				return;
		}
	}
	if (strmatch(leaf, "local")) {
		if (yang_dnode_exists(admin, "./internal")) {
			earlier = yang_dnode_get(admin, "./internal");
			if (show_defaults || !yang_dnode_is_default(earlier, NULL))
				return;
		}
	}

	ebgp = yang_dnode_exists(admin, "./external") ? yang_dnode_get_uint8(admin, "./external")
						      : ZEBRA_EBGP_DISTANCE_DEFAULT;
	ibgp = yang_dnode_exists(admin, "./internal") ? yang_dnode_get_uint8(admin, "./internal")
						      : ZEBRA_IBGP_DISTANCE_DEFAULT;
	local = yang_dnode_exists(admin, "./local") ? yang_dnode_get_uint8(admin, "./local")
						    : ZEBRA_IBGP_DISTANCE_DEFAULT;

	if (!show_defaults && ebgp == ZEBRA_EBGP_DISTANCE_DEFAULT &&
	    ibgp == ZEBRA_IBGP_DISTANCE_DEFAULT && local == ZEBRA_IBGP_DISTANCE_DEFAULT)
		return;

	vty_out(vty, "  distance bgp %u %u %u\n", ebgp, ibgp, local);
}

static int bgp_nb_distance_route_apply(const struct lyd_node *dnode)
{
	afi_t afi;
	safi_t safi;
	const char *prefix;
	const char *acl = NULL;
	uint8_t distance;
	char err[256];

	if (!bgp_nb_dnode_afi_safi(dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	prefix = yang_dnode_get_string(dnode, "./prefix");
	distance = yang_dnode_get_uint8(dnode, "./distance");
	if (yang_dnode_exists(dnode, "./access-list"))
		acl = yang_dnode_get_string(dnode, "./access-list");

	if (bgp_distance_source_set(afi, safi, distance, prefix, acl, err, sizeof(err)) < 0)
		return NB_ERR_RESOURCE;
	return NB_OK;
}

int bgp_nb_distance_route_create(struct nb_cb_create_args *args)
{
	struct prefix p;

	if (args->event == NB_EV_VALIDATE) {
		if (!str2prefix(yang_dnode_get_string(args->dnode, "./prefix"), &p)) {
			snprintfrr(args->errmsg, args->errmsg_len, "Malformed prefix");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_distance_route_apply(args->dnode);
}

int bgp_nb_distance_route_destroy(struct nb_cb_destroy_args *args)
{
	afi_t afi;
	safi_t safi;
	const char *prefix;
	uint8_t distance;
	char err[256];

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	if (!bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	prefix = yang_dnode_get_string(args->dnode, "./prefix");
	distance = yang_dnode_get_uint8(args->dnode, "./distance");
	bgp_distance_source_unset(afi, safi, distance, prefix, err, sizeof(err));
	return NB_OK;
}

void bgp_nb_cli_show_distance_route(struct vty *vty, const struct lyd_node *dnode,
				    bool show_defaults)
{
	vty_out(vty, "  distance %u %s", yang_dnode_get_uint8(dnode, "./distance"),
		yang_dnode_get_string(dnode, "./prefix"));
	if (yang_dnode_exists(dnode, "./access-list"))
		vty_out(vty, " %s", yang_dnode_get_string(dnode, "./access-list"));
	vty_out(vty, "\n");
}

int bgp_nb_distance_route_distance_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_distance_route_apply(
		yang_dnode_get_parent(args->dnode, "admin-distance-route"));
}

int bgp_nb_distance_route_acl_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_distance_route_apply(
		yang_dnode_get_parent(args->dnode, "admin-distance-route"));
}

int bgp_nb_distance_route_acl_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_distance_route_apply(
		yang_dnode_get_parent(args->dnode, "admin-distance-route"));
}

/*
 * table-map → filter-config/rmap-export
 */
int bgp_nb_table_map_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	bgp_table_map_set(bgp, afi, safi, yang_dnode_get_string(args->dnode, NULL));
	return NB_OK;
}

int bgp_nb_table_map_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	bgp_table_map_unset(bgp, afi, safi);
	return NB_OK;
}

void bgp_nb_cli_show_table_map(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, "  table-map %s\n", yang_dnode_get_string(dnode, NULL));
}

/*
 * route-flap-dampening → bgp dampening
 */
static int bgp_nb_dampening_apply(const struct lyd_node *dnode)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	const struct lyd_node *damp;
	uint8_t half_min;
	uint16_t reuse, suppress;
	uint8_t max_min;

	damp = yang_dnode_get_parent(dnode, "route-flap-dampening");
	if (!damp)
		damp = dnode;

	bgp = nb_running_get_entry(damp, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(damp, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	if (!yang_dnode_exists(damp, "./enable") || !yang_dnode_get_bool(damp, "./enable")) {
		bgp_damp_disable(bgp, afi, safi);
		return NB_OK;
	}

	half_min = yang_dnode_exists(damp, "./reach-decay")
			   ? yang_dnode_get_uint8(damp, "./reach-decay")
			   : DEFAULT_HALF_LIFE;
	reuse = yang_dnode_exists(damp, "./reuse-above")
			? yang_dnode_get_uint16(damp, "./reuse-above")
			: DEFAULT_REUSE;
	suppress = yang_dnode_exists(damp, "./suppress-above")
			   ? yang_dnode_get_uint16(damp, "./suppress-above")
			   : DEFAULT_SUPPRESS;
	max_min = yang_dnode_exists(damp, "./unreach-decay")
			  ? yang_dnode_get_uint8(damp, "./unreach-decay")
			  : (uint8_t)(4 * half_min);

	if (suppress < reuse)
		return NB_ERR_VALIDATION;

	bgp_damp_enable(bgp, afi, safi, (time_t)half_min * 60, reuse, suppress,
			(time_t)max_min * 60);
	return NB_OK;
}

int bgp_nb_dampening_enable_modify(struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_VALIDATE) {
		const struct lyd_node *damp;
		uint16_t reuse, suppress;

		if (!yang_dnode_get_bool(args->dnode, NULL))
			return NB_OK;
		damp = yang_dnode_get_parent(args->dnode, "route-flap-dampening");
		if (!damp)
			return NB_OK;
		reuse = yang_dnode_exists(damp, "./reuse-above")
				? yang_dnode_get_uint16(damp, "./reuse-above")
				: DEFAULT_REUSE;
		suppress = yang_dnode_exists(damp, "./suppress-above")
				   ? yang_dnode_get_uint16(damp, "./suppress-above")
				   : DEFAULT_SUPPRESS;
		if (suppress < reuse) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "Suppress value cannot be less than reuse value");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_dampening_apply(args->dnode);
}

int bgp_nb_dampening_enable_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_dampening_apply(args->dnode);
}

int bgp_nb_dampening_param_modify(struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_VALIDATE) {
		const struct lyd_node *damp;
		uint16_t reuse, suppress;

		damp = yang_dnode_get_parent(args->dnode, "route-flap-dampening");
		if (!damp)
			return NB_OK;
		reuse = yang_dnode_exists(damp, "./reuse-above")
				? yang_dnode_get_uint16(damp, "./reuse-above")
				: DEFAULT_REUSE;
		suppress = yang_dnode_exists(damp, "./suppress-above")
				   ? yang_dnode_get_uint16(damp, "./suppress-above")
				   : DEFAULT_SUPPRESS;
		if (suppress < reuse) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "Suppress value cannot be less than reuse value");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_dampening_apply(args->dnode);
}

int bgp_nb_dampening_param_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_dampening_apply(args->dnode);
}

void bgp_nb_cli_show_dampening(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const struct lyd_node *damp = yang_dnode_get_parent(dnode, "route-flap-dampening");
	uint8_t half_min, max_min;
	uint16_t reuse, suppress;

	if (!damp || !yang_dnode_get_bool(dnode, NULL))
		return;

	half_min = yang_dnode_exists(damp, "./reach-decay")
			   ? yang_dnode_get_uint8(damp, "./reach-decay")
			   : DEFAULT_HALF_LIFE;
	reuse = yang_dnode_exists(damp, "./reuse-above")
			? yang_dnode_get_uint16(damp, "./reuse-above")
			: DEFAULT_REUSE;
	suppress = yang_dnode_exists(damp, "./suppress-above")
			   ? yang_dnode_get_uint16(damp, "./suppress-above")
			   : DEFAULT_SUPPRESS;
	max_min = yang_dnode_exists(damp, "./unreach-decay")
			  ? yang_dnode_get_uint8(damp, "./unreach-decay")
			  : (uint8_t)(4 * half_min);

	if (half_min == DEFAULT_HALF_LIFE && reuse == DEFAULT_REUSE &&
	    suppress == DEFAULT_SUPPRESS && max_min == 4 * half_min)
		vty_out(vty, "  bgp dampening\n");
	else if (reuse == DEFAULT_REUSE && suppress == DEFAULT_SUPPRESS && max_min == 4 * half_min)
		vty_out(vty, "  bgp dampening %u\n", half_min);
	else
		vty_out(vty, "  bgp dampening %u %u %u %u\n", half_min, reuse, suppress, max_min);
}

/*
 * Neighbor / peer-group AF route-flap-dampening
 */
static int bgp_nb_peer_dampening_apply(const struct lyd_node *dnode)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	const struct lyd_node *damp;
	uint8_t half_min;
	uint16_t reuse, suppress;
	uint8_t max_min;

	damp = yang_dnode_get_parent(dnode, "route-flap-dampening");
	if (!damp)
		damp = dnode;

	peer = bgp_nb_config_peer(damp);
	if (!peer || !bgp_nb_dnode_afi_safi(damp, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	if (!yang_dnode_exists(damp, "./enable") || !yang_dnode_get_bool(damp, "./enable")) {
		bgp_peer_damp_disable(peer, afi, safi);
		return NB_OK;
	}

	half_min = yang_dnode_exists(damp, "./reach-decay")
			   ? yang_dnode_get_uint8(damp, "./reach-decay")
			   : DEFAULT_HALF_LIFE;
	reuse = yang_dnode_exists(damp, "./reuse-above")
			? yang_dnode_get_uint16(damp, "./reuse-above")
			: DEFAULT_REUSE;
	suppress = yang_dnode_exists(damp, "./suppress-above")
			   ? yang_dnode_get_uint16(damp, "./suppress-above")
			   : DEFAULT_SUPPRESS;
	max_min = yang_dnode_exists(damp, "./unreach-decay")
			  ? yang_dnode_get_uint8(damp, "./unreach-decay")
			  : (uint8_t)(4 * half_min);

	if (suppress < reuse)
		return NB_ERR_VALIDATION;

	bgp_peer_damp_enable(peer, afi, safi, (time_t)half_min * 60, reuse, suppress,
			     (time_t)max_min * 60);
	return NB_OK;
}

int bgp_nb_peer_dampening_enable_modify(struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_VALIDATE) {
		const struct lyd_node *damp;
		uint16_t reuse, suppress;

		if (!yang_dnode_get_bool(args->dnode, NULL))
			return NB_OK;
		damp = yang_dnode_get_parent(args->dnode, "route-flap-dampening");
		if (!damp)
			return NB_OK;
		reuse = yang_dnode_exists(damp, "./reuse-above")
				? yang_dnode_get_uint16(damp, "./reuse-above")
				: DEFAULT_REUSE;
		suppress = yang_dnode_exists(damp, "./suppress-above")
				   ? yang_dnode_get_uint16(damp, "./suppress-above")
				   : DEFAULT_SUPPRESS;
		if (suppress < reuse) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "Suppress value cannot be less than reuse value");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_peer_dampening_apply(args->dnode);
}

int bgp_nb_peer_dampening_enable_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_peer_dampening_apply(args->dnode);
}

int bgp_nb_peer_dampening_param_modify(struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_VALIDATE) {
		const struct lyd_node *damp;
		uint16_t reuse, suppress;

		damp = yang_dnode_get_parent(args->dnode, "route-flap-dampening");
		if (!damp)
			return NB_OK;
		reuse = yang_dnode_exists(damp, "./reuse-above")
				? yang_dnode_get_uint16(damp, "./reuse-above")
				: DEFAULT_REUSE;
		suppress = yang_dnode_exists(damp, "./suppress-above")
				   ? yang_dnode_get_uint16(damp, "./suppress-above")
				   : DEFAULT_SUPPRESS;
		if (suppress < reuse) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "Suppress value cannot be less than reuse value");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_peer_dampening_apply(args->dnode);
}

int bgp_nb_peer_dampening_param_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_peer_dampening_apply(args->dnode);
}

void bgp_nb_cli_show_peer_dampening(struct vty *vty, const struct lyd_node *dnode,
				    bool show_defaults)
{
	const struct lyd_node *damp = yang_dnode_get_parent(dnode, "route-flap-dampening");
	uint8_t half_min, max_min;
	uint16_t reuse, suppress;
	const char *peer_name;

	if (!damp || !yang_dnode_get_bool(dnode, NULL))
		return;

	peer_name = bgp_nb_config_peer_name(dnode);
	half_min = yang_dnode_exists(damp, "./reach-decay")
			   ? yang_dnode_get_uint8(damp, "./reach-decay")
			   : DEFAULT_HALF_LIFE;
	reuse = yang_dnode_exists(damp, "./reuse-above")
			? yang_dnode_get_uint16(damp, "./reuse-above")
			: DEFAULT_REUSE;
	suppress = yang_dnode_exists(damp, "./suppress-above")
			   ? yang_dnode_get_uint16(damp, "./suppress-above")
			   : DEFAULT_SUPPRESS;
	max_min = yang_dnode_exists(damp, "./unreach-decay")
			  ? yang_dnode_get_uint8(damp, "./unreach-decay")
			  : (uint8_t)(4 * half_min);

	if (half_min == DEFAULT_HALF_LIFE && reuse == DEFAULT_REUSE &&
	    suppress == DEFAULT_SUPPRESS && max_min == 4 * half_min)
		vty_out(vty, "  neighbor %s dampening\n", peer_name);
	else if (reuse == DEFAULT_REUSE && suppress == DEFAULT_SUPPRESS && max_min == 4 * half_min)
		vty_out(vty, "  neighbor %s dampening %u\n", peer_name, half_min);
	else
		vty_out(vty, "  neighbor %s dampening %u %u %u %u\n", peer_name, half_min, reuse,
			suppress, max_min);
}

/*
 * AF-level UPA (upa originate-all / max-routes / drop)
 */
int bgp_nb_upa_originate_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	bool enable;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;
	if (safi != SAFI_UNICAST)
		return NB_ERR_VALIDATION;

	enable = yang_dnode_get_bool(args->dnode, NULL);
	if (enable == bgp->upa_enabled[afi][safi])
		return NB_OK;

	if (enable) {
		bgp->upa_enabled[afi][safi] = true;
		bgp_upa_originate_global(bgp, afi, safi);
	} else {
		bgp_upa_withdraw_global(bgp, afi, safi);
		bgp->upa_enabled[afi][safi] = false;
	}
	return NB_OK;
}

int bgp_nb_upa_originate_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	if (!bgp->upa_enabled[afi][safi])
		return NB_OK;

	bgp_upa_withdraw_global(bgp, afi, safi);
	bgp->upa_enabled[afi][safi] = false;
	return NB_OK;
}

void bgp_nb_cli_show_upa_originate(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL) || show_defaults)
		vty_out(vty, "  upa originate-all\n");
}

int bgp_nb_upa_max_routes_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	bgp->upa_max_routes[afi][safi] = yang_dnode_get_uint32(args->dnode, NULL);
	return NB_OK;
}

int bgp_nb_upa_max_routes_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	bgp->upa_max_routes[afi][safi] = 0;
	return NB_OK;
}

void bgp_nb_cli_show_upa_max_routes(struct vty *vty, const struct lyd_node *dnode,
				    bool show_defaults)
{
	uint32_t max = yang_dnode_get_uint32(dnode, NULL);

	if (max || show_defaults)
		vty_out(vty, "  upa max-routes %u\n", max);
}

int bgp_nb_upa_drop_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	bool drop;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	drop = yang_dnode_get_bool(args->dnode, NULL);
	if (drop == bgp->upa_drop[afi][safi])
		return NB_OK;

	bgp->upa_drop[afi][safi] = drop;
	if (bgp->upa_enabled[afi][safi]) {
		bgp_upa_withdraw_global(bgp, afi, safi);
		bgp_upa_originate_global(bgp, afi, safi);
	}
	return NB_OK;
}

int bgp_nb_upa_drop_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	if (!bgp->upa_drop[afi][safi])
		return NB_OK;

	bgp->upa_drop[afi][safi] = false;
	if (bgp->upa_enabled[afi][safi]) {
		bgp_upa_withdraw_global(bgp, afi, safi);
		bgp_upa_originate_global(bgp, afi, safi);
	}
	return NB_OK;
}

void bgp_nb_cli_show_upa_drop(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL) || show_defaults)
		vty_out(vty, "  upa drop\n");
}

/*
 * ipv6 nexthop prefer-global
 */
int bgp_nb_nexthop_prefer_global_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	bool enable;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	if (afi != AFI_IP6 || !BGP_IPV6_SAFI_SUPPORTS_NEXTHOP_PREFER_GLOBAL(safi))
		return NB_ERR_VALIDATION;

	enable = yang_dnode_get_bool(args->dnode, NULL);
	if (bgp->nexthop_prefer_global[afi][safi] == enable)
		return NB_OK;

	bgp->nexthop_prefer_global[afi][safi] = enable;
	bgp_clear_soft_in(bgp, afi, safi);
	return NB_OK;
}

int bgp_nb_nexthop_prefer_global_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	if (afi != AFI_IP6 || !BGP_IPV6_SAFI_SUPPORTS_NEXTHOP_PREFER_GLOBAL(safi))
		return NB_OK;

	/* Restore YANG default (false). */
	if (!bgp->nexthop_prefer_global[afi][safi])
		return NB_OK;

	bgp->nexthop_prefer_global[afi][safi] = false;
	bgp_clear_soft_in(bgp, afi, safi);
	return NB_OK;
}

void bgp_nb_cli_show_nexthop_prefer_global(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "  nexthop prefer-global\n");
	else if (show_defaults)
		vty_out(vty, "  no nexthop prefer-global\n");
}

/*
 * Global L2VPN EVPN AF knobs
 */

/*
 * EVPN_ENABLED is set on APPLY of advertise-all-vni. VALIDATE of sibling
 * leaves in the same candidate must treat a pending advertise-all-vni as
 * enabling EVPN, matching classic sequential CLI checks.
 *
 * Tenant L3 VRFs commonly configure advertise-default-gw / advertise-svi-ip
 * under address-family l2vpn evpn without advertise-all-vni (that knob lives
 * on the underlay EVPN VRF). Allow those when an EVPN VRF already exists.
 */
static bool bgp_nb_evpn_enabled_in_candidate(struct bgp *bgp, const struct lyd_node *dnode)
{
	struct bgp *bgp_evpn;

	if (EVPN_ENABLED(bgp))
		return true;
	if (yang_dnode_exists(dnode, "../advertise-all-vni") &&
	    yang_dnode_get_bool(dnode, "../advertise-all-vni"))
		return true;

	bgp_evpn = bgp_get_evpn();
	if (bgp_evpn && bgp_evpn != bgp && EVPN_ENABLED(bgp_evpn))
		return true;

	return false;
}

int bgp_nb_evpn_advertise_all_vni_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct bgp *bgp_evpn;

	if (args->event == NB_EV_VALIDATE) {
		if (!yang_dnode_get_bool(args->dnode, NULL))
			return NB_OK;
		bgp = nb_running_get_entry(args->dnode, NULL, false);
		if (!bgp)
			return NB_OK;
		bgp_evpn = bgp_get_evpn();
		if (bgp_evpn && bgp_evpn != bgp && EVPN_ENABLED(bgp_evpn)) {
			snprintfrr(args->errmsg, args->errmsg_len, "Please unconfigure EVPN in %s",
				   bgp_evpn->name_pretty);
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp)
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL))
		evpn_set_advertise_all_vni(bgp);
	else
		evpn_unset_advertise_all_vni(bgp);
	return NB_OK;
}

int bgp_nb_evpn_advertise_all_vni_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp)
		return NB_OK;
	evpn_unset_advertise_all_vni(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_evpn_advertise_all_vni(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "  advertise-all-vni\n");
}

static bool bgp_nb_evpn_autort_rfc8365_is_import(const struct lyd_node *dnode)
{
	return strmatch(dnode->schema->name, "import-autort-rfc8365-compatible");
}

int bgp_nb_evpn_autort_rfc8365_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	bool is_import;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp)
		return NB_ERR_NOT_FOUND;

	is_import = bgp_nb_evpn_autort_rfc8365_is_import(args->dnode);
	if (yang_dnode_get_bool(args->dnode, NULL))
		evpn_set_autort_rfc8365(bgp, is_import, !is_import);
	else
		evpn_unset_autort_rfc8365(bgp, is_import, !is_import);
	return NB_OK;
}

int bgp_nb_evpn_autort_rfc8365_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	bool is_import;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp)
		return NB_OK;

	is_import = bgp_nb_evpn_autort_rfc8365_is_import(args->dnode);
	evpn_unset_autort_rfc8365(bgp, is_import, !is_import);
	return NB_OK;
}

void bgp_nb_cli_show_evpn_autort_rfc8365(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "  auto-route-target %s rfc8365-compatible\n",
			bgp_nb_evpn_autort_rfc8365_is_import(dnode) ? "import" : "export");
}

int bgp_nb_evpn_advertise_default_gw_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event == NB_EV_VALIDATE) {
		if (!yang_dnode_get_bool(args->dnode, NULL))
			return NB_OK;
		bgp = nb_running_get_entry(args->dnode, NULL, false);
		if (!bgp)
			return NB_OK;
		if (!bgp_nb_evpn_enabled_in_candidate(bgp, args->dnode)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "This command is only supported under the EVPN VRF");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp)
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL))
		evpn_set_advertise_default_gw(bgp, NULL);
	else
		evpn_unset_advertise_default_gw(bgp, NULL);
	return NB_OK;
}

int bgp_nb_evpn_advertise_default_gw_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp)
		return NB_OK;
	evpn_unset_advertise_default_gw(bgp, NULL);
	return NB_OK;
}

void bgp_nb_cli_show_evpn_advertise_default_gw(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "  advertise-default-gw\n");
}

int bgp_nb_evpn_advertise_svi_ip_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event == NB_EV_VALIDATE) {
		if (!yang_dnode_get_bool(args->dnode, NULL))
			return NB_OK;
		bgp = nb_running_get_entry(args->dnode, NULL, false);
		if (!bgp)
			return NB_OK;
		if (!bgp_nb_evpn_enabled_in_candidate(bgp, args->dnode)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "This command is only supported under EVPN VRF");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp)
		return NB_ERR_NOT_FOUND;

	evpn_set_advertise_svi_macip(bgp, NULL, yang_dnode_get_bool(args->dnode, NULL) ? 1 : 0);
	return NB_OK;
}

int bgp_nb_evpn_advertise_svi_ip_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp)
		return NB_OK;
	evpn_set_advertise_svi_macip(bgp, NULL, 0);
	return NB_OK;
}

void bgp_nb_cli_show_evpn_advertise_svi_ip(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "  advertise-svi-ip\n");
}

int bgp_nb_evpn_resolve_overlay_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event == NB_EV_VALIDATE) {
		bgp = nb_running_get_entry(args->dnode, NULL, false);
		if (!bgp)
			return NB_OK;
		if (bgp != bgp_get_evpn()) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "This command is only supported under EVPN VRF");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp)
		return NB_ERR_NOT_FOUND;

	bgp_evpn_set_unset_resolve_overlay_index(bgp, yang_dnode_get_bool(args->dnode, NULL));
	return NB_OK;
}

int bgp_nb_evpn_resolve_overlay_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp)
		return NB_OK;
	bgp_evpn_set_unset_resolve_overlay_index(bgp, false);
	return NB_OK;
}

void bgp_nb_cli_show_evpn_resolve_overlay(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "  enable-resolve-overlay-index\n");
}

int bgp_nb_evpn_flooding_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *val;
	enum vxlan_flood_control flood_ctrl;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp)
		return NB_ERR_NOT_FOUND;

	val = yang_dnode_get_string(args->dnode, NULL);
	if (strmatch(val, "disable"))
		flood_ctrl = VXLAN_FLOOD_DISABLED;
	else
		flood_ctrl = VXLAN_FLOOD_HEAD_END_REPL;

	if (bgp->vxlan_flood_ctrl == flood_ctrl)
		return NB_OK;

	bgp->vxlan_flood_ctrl = flood_ctrl;
	bgp_evpn_flood_control_change(bgp);
	return NB_OK;
}

int bgp_nb_evpn_flooding_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp)
		return NB_OK;

	if (bgp->vxlan_flood_ctrl == VXLAN_FLOOD_HEAD_END_REPL)
		return NB_OK;

	bgp->vxlan_flood_ctrl = VXLAN_FLOOD_HEAD_END_REPL;
	bgp_evpn_flood_control_change(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_evpn_flooding(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults)
{
	const char *val = yang_dnode_get_string(dnode, NULL);

	if (strmatch(val, "disable"))
		vty_out(vty, "  flooding disable\n");
	else if (show_defaults)
		vty_out(vty, "  flooding head-end-replication\n");
}

int bgp_nb_evpn_macvrf_soo_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct bgp *bgp_evpn;
	struct ecommunity *ecomm_soo;
	const char *soo;

	if (args->event == NB_EV_VALIDATE) {
		bgp = nb_running_get_entry(args->dnode, NULL, false);
		bgp_evpn = bgp_get_evpn();
		if (!bgp)
			return NB_OK;
		if (!bgp_evpn || !bgp_evpn->evpn_info) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "EVPN underlay is not configured");
			return NB_ERR_VALIDATION;
		}
		if (bgp != bgp_evpn) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "Please configure MAC-VRF SoO in the EVPN underlay: %s",
				   bgp_evpn->name_pretty);
			return NB_ERR_VALIDATION;
		}
		soo = yang_dnode_get_string(args->dnode, NULL);
		ecomm_soo = ecommunity_str2com(soo, ECOMMUNITY_SITE_ORIGIN, 0);
		if (!ecomm_soo) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "Malformed SoO extended community");
			return NB_ERR_VALIDATION;
		}
		ecommunity_free(&ecomm_soo);
		return NB_OK;
	}
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp_evpn = bgp_get_evpn();
	if (!bgp_evpn || !bgp_evpn->evpn_info)
		return NB_ERR_NOT_FOUND;

	soo = yang_dnode_get_string(args->dnode, NULL);
	ecomm_soo = ecommunity_str2com(soo, ECOMMUNITY_SITE_ORIGIN, 0);
	if (!ecomm_soo)
		return NB_ERR_VALIDATION;
	ecommunity_str(ecomm_soo);
	bgp_evpn_handle_global_macvrf_soo_change(bgp_evpn, ecomm_soo);
	return NB_OK;
}

int bgp_nb_evpn_macvrf_soo_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp_evpn;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp_evpn = bgp_get_evpn();
	if (!bgp_evpn || !bgp_evpn->evpn_info)
		return NB_OK;

	bgp_evpn_handle_global_macvrf_soo_change(bgp_evpn, NULL);
	return NB_OK;
}

void bgp_nb_cli_show_evpn_macvrf_soo(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults)
{
	vty_out(vty, "  mac-vrf soo %s\n", yang_dnode_get_string(dnode, NULL));
}

/*
 * EVPN duplicate-address-detection
 */
static int bgp_nb_evpn_dad_apply(const struct lyd_node *dnode)
{
	struct bgp *bgp;
	const struct lyd_node *dad;
	bool enable;
	uint16_t max_moves, time_s;

	dad = yang_dnode_get_parent(dnode, "duplicate-address-detection");
	if (!dad)
		dad = dnode;

	bgp = nb_running_get_entry(dad, NULL, true);
	if (!bgp || !bgp->evpn_info)
		return NB_ERR_NOT_FOUND;

	enable = !yang_dnode_exists(dad, "./enable") || yang_dnode_get_bool(dad, "./enable");
	max_moves = yang_dnode_exists(dad, "./max-moves")
			    ? yang_dnode_get_uint16(dad, "./max-moves")
			    : EVPN_DAD_DEFAULT_MAX_MOVES;
	time_s = yang_dnode_exists(dad, "./time") ? yang_dnode_get_uint16(dad, "./time")
						  : EVPN_DAD_DEFAULT_TIME;

	bgp->evpn_info->dup_addr_detect = enable;
	bgp->evpn_info->dad_max_moves = max_moves;
	bgp->evpn_info->dad_time = time_s;

	if (yang_dnode_exists(dad, "./freeze-permanent")) {
		bgp->evpn_info->dad_freeze = true;
		bgp->evpn_info->dad_freeze_time = 0;
	} else if (yang_dnode_exists(dad, "./freeze-time")) {
		bgp->evpn_info->dad_freeze = true;
		bgp->evpn_info->dad_freeze_time = yang_dnode_get_uint16(dad, "./freeze-time");
	} else {
		bgp->evpn_info->dad_freeze = false;
		bgp->evpn_info->dad_freeze_time = 0;
	}

	bgp_zebra_dup_addr_detection(bgp);
	return NB_OK;
}

int bgp_nb_evpn_dad_enable_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event == NB_EV_VALIDATE) {
		bgp = nb_running_get_entry(args->dnode, NULL, false);
		if (!bgp)
			return NB_OK;
		if (!EVPN_ENABLED(bgp)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "This command is only supported under the EVPN VRF");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_evpn_dad_apply(args->dnode);
}

int bgp_nb_evpn_dad_enable_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_evpn_dad_apply(args->dnode);
}

int bgp_nb_evpn_dad_param_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event == NB_EV_VALIDATE) {
		bgp = nb_running_get_entry(args->dnode, NULL, false);
		if (!bgp)
			return NB_OK;
		if (!EVPN_ENABLED(bgp)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "This command is only supported under the EVPN VRF");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_evpn_dad_apply(args->dnode);
}

int bgp_nb_evpn_dad_param_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_evpn_dad_apply(args->dnode);
}

void bgp_nb_cli_show_evpn_dad_enable(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "  no dup-addr-detection\n");
}

void bgp_nb_cli_show_evpn_dad_max_moves(struct vty *vty, const struct lyd_node *dnode,
					bool show_defaults)
{
	const struct lyd_node *dad = yang_dnode_get_parent(dnode, "duplicate-address-detection");
	uint16_t max_moves, time_s;

	if (!dad)
		return;
	if (yang_dnode_exists(dad, "./enable") && !yang_dnode_get_bool(dad, "./enable"))
		return;

	max_moves = yang_dnode_get_uint16(dnode, NULL);
	time_s = yang_dnode_exists(dad, "./time") ? yang_dnode_get_uint16(dad, "./time")
						  : EVPN_DAD_DEFAULT_TIME;
	if (max_moves == EVPN_DAD_DEFAULT_MAX_MOVES && time_s == EVPN_DAD_DEFAULT_TIME)
		return;

	vty_out(vty, "  dup-addr-detection max-moves %u time %u\n", max_moves, time_s);
}

void bgp_nb_cli_show_evpn_dad_time(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults)
{
	const struct lyd_node *dad = yang_dnode_get_parent(dnode, "duplicate-address-detection");
	uint16_t time_s;

	if (!dad)
		return;
	/*
	 * max-moves owns the combined line when its callback runs. A default
	 * max-moves is skipped, so a changed time has to be printed here.
	 * show_defaults still visits max-moves, and that callback prints.
	 */
	if (yang_dnode_exists(dad, "./max-moves")) {
		const struct lyd_node *moves = yang_dnode_get(dad, "./max-moves");

		if (show_defaults || (moves && !yang_dnode_is_default(moves, NULL)))
			return;
	}
	if (yang_dnode_exists(dad, "./enable") && !yang_dnode_get_bool(dad, "./enable"))
		return;

	time_s = yang_dnode_get_uint16(dnode, NULL);
	if (time_s == EVPN_DAD_DEFAULT_TIME)
		return;

	vty_out(vty, "  dup-addr-detection max-moves %u time %u\n", EVPN_DAD_DEFAULT_MAX_MOVES,
		time_s);
}

void bgp_nb_cli_show_evpn_dad_freeze_time(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults)
{
	vty_out(vty, "  dup-addr-detection freeze %u\n", yang_dnode_get_uint16(dnode, NULL));
}

int bgp_nb_evpn_dad_freeze_permanent_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;

	if (args->event == NB_EV_VALIDATE) {
		bgp = nb_running_get_entry(args->dnode, NULL, false);
		if (!bgp)
			return NB_OK;
		if (!EVPN_ENABLED(bgp)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "This command is only supported under the EVPN VRF");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_evpn_dad_apply(args->dnode);
}

int bgp_nb_evpn_dad_freeze_permanent_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_evpn_dad_apply(args->dnode);
}

void bgp_nb_cli_show_evpn_dad_freeze_permanent(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults)
{
	vty_out(vty, "  dup-addr-detection freeze permanent\n");
}

/*
 * EVPN multihoming knobs (process-wide via bgp_mh_info)
 */
int bgp_nb_evpn_use_es_l3nhg_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	bgp_mh_info->host_routes_use_l3nhg = yang_dnode_get_bool(args->dnode, NULL);
	return NB_OK;
}

int bgp_nb_evpn_use_es_l3nhg_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	bgp_mh_info->host_routes_use_l3nhg = BGP_EVPN_MH_USE_ES_L3NHG_DEF;
	return NB_OK;
}

void bgp_nb_cli_show_evpn_use_es_l3nhg(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults)
{
	bool enable = yang_dnode_get_bool(dnode, NULL);

	if (enable == BGP_EVPN_MH_USE_ES_L3NHG_DEF && !show_defaults)
		return;
	if (enable)
		vty_out(vty, "  use-es-l3nhg\n");
	else
		vty_out(vty, "  no use-es-l3nhg\n");
}

int bgp_nb_evpn_disable_ead_evi_rx_modify(struct nb_cb_modify_args *args)
{
	bool enable_rx;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	enable_rx = !yang_dnode_get_bool(args->dnode, NULL);
	if (enable_rx != bgp_mh_info->enable_ead_evi_rx) {
		bgp_mh_info->enable_ead_evi_rx = enable_rx;
		bgp_evpn_switch_ead_evi_rx();
	}
	return NB_OK;
}

int bgp_nb_evpn_disable_ead_evi_rx_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	if (bgp_mh_info->enable_ead_evi_rx != BGP_EVPN_MH_EAD_EVI_RX_DEF) {
		bgp_mh_info->enable_ead_evi_rx = BGP_EVPN_MH_EAD_EVI_RX_DEF;
		bgp_evpn_switch_ead_evi_rx();
	}
	return NB_OK;
}

void bgp_nb_cli_show_evpn_disable_ead_evi_rx(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults)
{
	bool disable = yang_dnode_get_bool(dnode, NULL);

	if (!disable && !show_defaults)
		return;
	if (disable)
		vty_out(vty, "  disable-ead-evi-rx\n");
	else
		vty_out(vty, "  no disable-ead-evi-rx\n");
}

int bgp_nb_evpn_disable_ead_evi_tx_modify(struct nb_cb_modify_args *args)
{
	bool enable_tx;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	enable_tx = !yang_dnode_get_bool(args->dnode, NULL);
	if (enable_tx != bgp_mh_info->enable_ead_evi_tx) {
		bgp_mh_info->enable_ead_evi_tx = enable_tx;
		bgp_evpn_switch_ead_evi_tx();
	}
	return NB_OK;
}

int bgp_nb_evpn_disable_ead_evi_tx_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	if (bgp_mh_info->enable_ead_evi_tx != BGP_EVPN_MH_EAD_EVI_TX_DEF) {
		bgp_mh_info->enable_ead_evi_tx = BGP_EVPN_MH_EAD_EVI_TX_DEF;
		bgp_evpn_switch_ead_evi_tx();
	}
	return NB_OK;
}

void bgp_nb_cli_show_evpn_disable_ead_evi_tx(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults)
{
	bool disable = yang_dnode_get_bool(dnode, NULL);

	if (!disable && !show_defaults)
		return;
	if (disable)
		vty_out(vty, "  disable-ead-evi-tx\n");
	else
		vty_out(vty, "  no disable-ead-evi-tx\n");
}

int bgp_nb_evpn_ead_es_frag_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	bgp_mh_info->evi_per_es_frag = yang_dnode_get_uint16(args->dnode, NULL);
	return NB_OK;
}

int bgp_nb_evpn_ead_es_frag_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	bgp_mh_info->evi_per_es_frag = BGP_EVPN_MAX_EVI_PER_ES_FRAG;
	return NB_OK;
}

void bgp_nb_cli_show_evpn_ead_es_frag(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults)
{
	uint16_t limit = yang_dnode_get_uint16(dnode, NULL);

	if (limit == BGP_EVPN_MAX_EVI_PER_ES_FRAG && !show_defaults)
		return;
	vty_out(vty, "  ead-es-frag evi-limit %u\n", limit);
}

/*
 * EVPN default-originate ipv4|ipv6
 */
static afi_t bgp_nb_evpn_default_orig_afi(const struct lyd_node *dnode)
{
	if (strmatch(dnode->schema->name, "ipv4"))
		return AFI_IP;
	if (strmatch(dnode->schema->name, "ipv6"))
		return AFI_IP6;
	return AFI_UNSPEC;
}

int bgp_nb_evpn_default_originate_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	afi_t afi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	afi = bgp_nb_evpn_default_orig_afi(args->dnode);
	if (!bgp || afi == AFI_UNSPEC)
		return NB_ERR_NOT_FOUND;

	evpn_process_default_originate_cmd(bgp, afi, yang_dnode_get_bool(args->dnode, NULL));
	return NB_OK;
}

int bgp_nb_evpn_default_originate_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	afi = bgp_nb_evpn_default_orig_afi(args->dnode);
	if (!bgp || afi == AFI_UNSPEC)
		return NB_OK;

	evpn_process_default_originate_cmd(bgp, afi, false);
	return NB_OK;
}

void bgp_nb_cli_show_evpn_default_originate(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		return;
	vty_out(vty, "  default-originate %s\n", dnode->schema->name);
}

/*
 * EVPN type-5 advertise ipv4|ipv6 <unicast|vpn> [gateway-ip] [route-map RMAP]
 * [skip-evpn-imported]
 */
static bool bgp_nb_evpn_type5_container(const struct lyd_node *dnode, const struct lyd_node **cont,
					afi_t *afi, safi_t *safi)
{
	const struct lyd_node *n;

	for (n = dnode; n; n = lyd_parent(n)) {
		const char *name = n->schema->name;

		if (strmatch(name, "ipv4-unicast")) {
			*afi = AFI_IP;
			*safi = SAFI_UNICAST;
		} else if (strmatch(name, "ipv6-unicast")) {
			*afi = AFI_IP6;
			*safi = SAFI_UNICAST;
		} else if (strmatch(name, "ipv4-vpn")) {
			*afi = AFI_IP;
			*safi = SAFI_MPLS_VPN;
		} else if (strmatch(name, "ipv6-vpn")) {
			*afi = AFI_IP6;
			*safi = SAFI_MPLS_VPN;
		} else
			continue;

		*cont = n;
		return true;
	}
	return false;
}

static void bgp_nb_evpn_type5_rmap_free(struct bgp *bgp, afi_t afi, safi_t safi)
{
	if (!bgp->adv_cmd_rmap[afi][safi].name)
		return;

	XFREE(MTYPE_ROUTE_MAP_NAME, bgp->adv_cmd_rmap[afi][safi].name);
	route_map_counter_decrement(bgp->adv_cmd_rmap[afi][safi].map);
	bgp->adv_cmd_rmap[afi][safi].name = NULL;
	bgp->adv_cmd_rmap[afi][safi].map = NULL;
}

/*
 * Reconcile the running Type-5 export state of one afi/safi with the
 * configured values of its YANG container.
 */
static int bgp_nb_evpn_type5_apply(const struct lyd_node *dnode, struct bgp *bgp_hint,
				   bool clear_rmap)
{
	struct bgp *bgp;
	const struct lyd_node *cont = NULL;
	afi_t afi;
	safi_t safi;
	bool enable, gw_ip = false, skip = false;
	const char *rmap = NULL;
	uint16_t flag_oi_none, flag_oi_gw_ip, suppress_flag;
	bool has_none, has_gw, was_advertising, adv_flag_changed;
	bool rmap_changed, skip_newly_enabled, skip_newly_disabled;
	const char *cur_rmap;
	uint16_t *flags;

	if (!bgp_nb_evpn_type5_container(dnode, &cont, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	/*
	 * Prefer an explicit VRF BGP (reapply after L3VNI attach). Fall back
	 * to resolving by control-plane-protocol name/vrf keys — walking
	 * nb_running_get_entry from ip-vrf leaves has bound the wrong
	 * instance and left type-5 / RD flags unset on the tenant VRF.
	 */
	bgp = bgp_hint;
	if (!bgp)
		bgp = bgp_nb_dnode_lookup_bgp(cont);
	if (!bgp)
		return NB_ERR_NOT_FOUND;

	flags = &bgp->af_flags[AFI_L2VPN][SAFI_EVPN];

	enable = yang_dnode_exists(cont, "./enable") && yang_dnode_get_bool(cont, "./enable");
	/*
	 * Destroy callbacks receive the running-tree dnode, so ./route-map
	 * still appears present. clear_rmap forces treat-as-absent.
	 */
	if (!clear_rmap && enable && yang_dnode_exists(cont, "./route-map"))
		rmap = yang_dnode_get_string(cont, "./route-map");

	if (safi == SAFI_UNICAST) {
		gw_ip = enable && yang_dnode_exists(cont, "./gateway-ip") &&
			yang_dnode_get_bool(cont, "./gateway-ip");
		skip = enable && yang_dnode_exists(cont, "./skip-evpn-imported") &&
		       yang_dnode_get_bool(cont, "./skip-evpn-imported");

		if (afi == AFI_IP) {
			flag_oi_none = BGP_L2VPN_EVPN_ADV_IPV4_UNICAST;
			flag_oi_gw_ip = BGP_L2VPN_EVPN_ADV_IPV4_UNICAST_GW_IP;
			suppress_flag = BGP_L2VPN_EVPN_SUPPRESS_IPV4_IMPORT_FROM_EVPN;
		} else {
			flag_oi_none = BGP_L2VPN_EVPN_ADV_IPV6_UNICAST;
			flag_oi_gw_ip = BGP_L2VPN_EVPN_ADV_IPV6_UNICAST_GW_IP;
			suppress_flag = BGP_L2VPN_EVPN_SUPPRESS_IPV6_IMPORT_FROM_EVPN;
		}
	} else {
		flag_oi_none = (afi == AFI_IP) ? BGP_L2VPN_EVPN_ADV_IPV4_VPN
					       : BGP_L2VPN_EVPN_ADV_IPV6_VPN;
		flag_oi_gw_ip = 0;
		suppress_flag = 0;
	}

	has_none = CHECK_FLAG(*flags, flag_oi_none);
	has_gw = flag_oi_gw_ip && CHECK_FLAG(*flags, flag_oi_gw_ip);
	was_advertising = has_none || has_gw;

	cur_rmap = bgp->adv_cmd_rmap[afi][safi].name;
	if (rmap && cur_rmap)
		rmap_changed = strcmp(rmap, cur_rmap) != 0;
	else
		rmap_changed = (rmap != NULL) != (cur_rmap != NULL);

	if (!enable) {
		if (was_advertising)
			bgp_evpn_withdraw_type5_routes(bgp, afi, safi);
		UNSET_FLAG(*flags, flag_oi_none);
		if (flag_oi_gw_ip)
			UNSET_FLAG(*flags, flag_oi_gw_ip);
		if (suppress_flag)
			UNSET_FLAG(*flags, suppress_flag);
		if (has_gw)
			bgp_addpath_type_changed(bgp);
		bgp_nb_evpn_type5_rmap_free(bgp, afi, safi);
		return NB_OK;
	}

	adv_flag_changed = gw_ip != has_gw;
	skip_newly_enabled = suppress_flag && skip && !CHECK_FLAG(*flags, suppress_flag);
	skip_newly_disabled = suppress_flag && !skip && CHECK_FLAG(*flags, suppress_flag);

	if (was_advertising && !adv_flag_changed && !rmap_changed && !skip_newly_enabled &&
	    !skip_newly_disabled)
		return NB_OK;

	/*
	 * A route-map or overlay-index change requires the already advertised
	 * Type-5 routes to be withdrawn before the flags are changed, for
	 * proper addpath handling in the withdraw logic.
	 */
	if (was_advertising && (rmap_changed || adv_flag_changed))
		bgp_evpn_withdraw_type5_routes(bgp, afi, safi);

	/*
	 * Enabling skip-evpn-imported drains exactly the EVPN-derived Type-5
	 * routes instead of withdrawing everything this VRF advertises.
	 */
	if (skip_newly_enabled) {
		if (was_advertising)
			bgp_evpn_withdraw_imported_type5_leaked_routes(bgp, afi);
		SET_FLAG(*flags, suppress_flag);
	}
	if (skip_newly_disabled)
		UNSET_FLAG(*flags, suppress_flag);

	if (rmap_changed) {
		bgp_nb_evpn_type5_rmap_free(bgp, afi, safi);
		if (rmap) {
			bgp->adv_cmd_rmap[afi][safi].name = XSTRDUP(MTYPE_ROUTE_MAP_NAME, rmap);
			bgp->adv_cmd_rmap[afi][safi].map = route_map_lookup_by_name(rmap);
			route_map_counter_increment(bgp->adv_cmd_rmap[afi][safi].map);
		}
	}

	if (adv_flag_changed || !was_advertising) {
		UNSET_FLAG(*flags, flag_oi_none);
		if (flag_oi_gw_ip)
			UNSET_FLAG(*flags, flag_oi_gw_ip);
		SET_FLAG(*flags, gw_ip ? flag_oi_gw_ip : flag_oi_none);
	}

	if (adv_flag_changed)
		/* Generate/cleanup addpath ids */
		bgp_addpath_type_changed(bgp);

	/*
	 * Run the advertise walk after first enabling Type-5 export, changing
	 * the route-map or overlay-index mode, or re-allowing EVPN-imported
	 * routes.  Enabling skip-evpn-imported only withdraws the EVPN-derived
	 * Type-5 routes.
	 */
	if ((advertise_type5_routes_bestpath(bgp, afi, safi) ||
	     advertise_type5_routes_multipath(bgp, afi, safi)) &&
	    (!was_advertising || rmap_changed || adv_flag_changed || skip_newly_disabled))
		bgp_evpn_advertise_type5_routes(bgp, afi, safi);

	/*
	 * Flags may have been set before L3VNI was live (advertise helpers
	 * no-op without l3vni). Once the VNI is attached, push VRF routes.
	 */
	if (bgp->l3vni)
		update_advertise_vrf_routes(bgp);

	return NB_OK;
}

int bgp_nb_evpn_type5_enable_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_evpn_type5_apply(args->dnode, NULL, false);
}

int bgp_nb_evpn_type5_enable_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_evpn_type5_apply(args->dnode, NULL, false);
}

int bgp_nb_evpn_type5_gateway_ip_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_evpn_type5_apply(args->dnode, NULL, false);
}

int bgp_nb_evpn_type5_gateway_ip_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_evpn_type5_apply(args->dnode, NULL, false);
}

int bgp_nb_evpn_type5_route_map_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_evpn_type5_apply(args->dnode, NULL, false);
}

int bgp_nb_evpn_type5_route_map_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_evpn_type5_apply(args->dnode, NULL, true);
}

int bgp_nb_evpn_type5_skip_evpn_imported_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_evpn_type5_apply(args->dnode, NULL, false);
}

int bgp_nb_evpn_type5_skip_evpn_imported_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_evpn_type5_apply(args->dnode, NULL, false);
}

void bgp_nb_cli_show_evpn_type5_enable(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults)
{
	const struct lyd_node *cont = NULL;
	afi_t afi;
	safi_t safi;
	const char *rmap = NULL;

	if (!yang_dnode_get_bool(dnode, NULL))
		return;

	if (!bgp_nb_evpn_type5_container(dnode, &cont, &afi, &safi))
		return;

	if (yang_dnode_exists(cont, "./route-map"))
		rmap = yang_dnode_get_string(cont, "./route-map");

	vty_out(vty, "  advertise %s %s", afi == AFI_IP ? "ipv4" : "ipv6",
		safi == SAFI_UNICAST ? "unicast" : "vpn");
	if (safi == SAFI_UNICAST && yang_dnode_exists(cont, "./gateway-ip") &&
	    yang_dnode_get_bool(cont, "./gateway-ip"))
		vty_out(vty, " gateway-ip");
	if (rmap)
		vty_out(vty, " route-map %s", rmap);
	if (safi == SAFI_UNICAST && yang_dnode_exists(cont, "./skip-evpn-imported") &&
	    yang_dnode_get_bool(cont, "./skip-evpn-imported"))
		vty_out(vty, " skip-evpn-imported");
	vty_out(vty, "\n");
}

/*
 * EVPN advertise-pip
 */
static void bgp_nb_evpn_pip_refresh(struct bgp *bgp_vrf)
{
	struct bgp *bgp_evpn;
	struct listnode *node;
	struct bgpevpn *vpn;

	if (!is_evpn_enabled())
		return;

	bgp_evpn = bgp_get_evpn();
	assert(bgp_evpn);

	update_advertise_vrf_routes(bgp_vrf);

	for (ALL_LIST_ELEMENTS_RO(bgp_vrf->l2vnis, node, vpn)) {
		if (!bgp_evpn_is_svi_macip_enabled(vpn))
			continue;
		update_routes_for_vni(bgp_evpn, vpn);
	}
}

static int bgp_nb_evpn_pip_apply(const struct lyd_node *dnode)
{
	struct bgp *bgp, *bgp_evpn;
	const struct lyd_node *cont;
	bool enable;
	bool has_ip, has_mac;
	struct in_addr ip;
	struct ethaddr mac;

	cont = yang_dnode_get_parent(dnode, "advertise-pip");
	if (!cont)
		cont = dnode;

	bgp = nb_running_get_entry(cont, NULL, true);
	if (!bgp || !bgp->evpn_info)
		return NB_ERR_NOT_FOUND;

	enable = !yang_dnode_exists(cont, "./enable") || yang_dnode_get_bool(cont, "./enable");
	has_ip = yang_dnode_exists(cont, "./system-ip");
	has_mac = yang_dnode_exists(cont, "./system-mac");
	if (has_ip)
		yang_dnode_get_ipv4(&ip, cont, "./system-ip");
	if (has_mac)
		yang_dnode_get_mac(&mac, cont, "./system-mac");

	bgp_evpn = bgp_get_evpn();

	if (!enable) {
		bgp->evpn_info->advertise_pip = false;
		memcpy(&bgp->evpn_info->pip_rmac, &bgp->rmac, ETH_ALEN);
		memset(&bgp->evpn_info->pip_rmac_static, 0, ETH_ALEN);
		bgp->evpn_info->pip_ip_static.ipaddr_v4.s_addr = INADDR_ANY;
		if (bgp_evpn)
			bgp->evpn_info->pip_ip.ipaddr_v4 = bgp_evpn->router_id;
		else
			bgp->evpn_info->pip_ip.ipaddr_v4.s_addr = INADDR_ANY;
		bgp_nb_evpn_pip_refresh(bgp);
		return NB_OK;
	}

	bgp->evpn_info->advertise_pip = true;

	if (has_ip) {
		ipaddr_set_v4(&bgp->evpn_info->pip_ip_static, ip);
		ipaddr_set_v4(&bgp->evpn_info->pip_ip, ip);
	} else {
		bgp->evpn_info->pip_ip_static.ipaddr_v4.s_addr = INADDR_ANY;
		if (bgp_evpn)
			bgp->evpn_info->pip_ip.ipaddr_v4 = bgp_evpn->router_id;
		else
			bgp->evpn_info->pip_ip.ipaddr_v4.s_addr = INADDR_ANY;
	}

	if (has_mac) {
		memcpy(&bgp->evpn_info->pip_rmac_static, &mac, ETH_ALEN);
		memcpy(&bgp->evpn_info->pip_rmac, &bgp->evpn_info->pip_rmac_static, ETH_ALEN);
	} else {
		memset(&bgp->evpn_info->pip_rmac_static, 0, ETH_ALEN);
		if (!is_zero_mac(&bgp->evpn_info->pip_rmac_zebra))
			memcpy(&bgp->evpn_info->pip_rmac, &bgp->evpn_info->pip_rmac_zebra,
			       ETH_ALEN);
		else
			memcpy(&bgp->evpn_info->pip_rmac, &bgp->rmac, ETH_ALEN);
	}

	bgp_nb_evpn_pip_refresh(bgp);
	return NB_OK;
}

int bgp_nb_evpn_advertise_pip_enable_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event == NB_EV_VALIDATE) {
		bgp = nb_running_get_entry(args->dnode, NULL, false);
		if (!bgp)
			return NB_OK;
		if (EVPN_ENABLED(bgp)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "This command is supported under L3VNI BGP EVPN VRF");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_evpn_pip_apply(args->dnode);
}

int bgp_nb_evpn_advertise_pip_enable_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_evpn_pip_apply(args->dnode);
}

int bgp_nb_evpn_advertise_pip_param_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event == NB_EV_VALIDATE) {
		bgp = nb_running_get_entry(args->dnode, NULL, false);
		if (!bgp)
			return NB_OK;
		if (EVPN_ENABLED(bgp)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "This command is supported under L3VNI BGP EVPN VRF");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_evpn_pip_apply(args->dnode);
}

int bgp_nb_evpn_advertise_pip_param_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_evpn_pip_apply(args->dnode);
}

void bgp_nb_cli_show_evpn_advertise_pip_enable(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults)
{
	const struct lyd_node *cont = yang_dnode_get_parent(dnode, "advertise-pip");
	const char *ip, *mac;

	if (!cont)
		return;

	if (!yang_dnode_get_bool(dnode, NULL)) {
		vty_out(vty, "  no advertise-pip\n");
		return;
	}

	if (yang_dnode_exists(cont, "./system-ip")) {
		ip = yang_dnode_get_string(cont, "./system-ip");
		vty_out(vty, "  advertise-pip ip %s", ip);
		if (yang_dnode_exists(cont, "./system-mac")) {
			mac = yang_dnode_get_string(cont, "./system-mac");
			vty_out(vty, " mac %s", mac);
		}
		vty_out(vty, "\n");
	}

	/* Plain "advertise-pip" is the default and is not written. */
}

/*
 * EVPN ead-es-route-target export (leaf-list)
 *
 * The export list is process-global. Two EVPN VRFs may configure the same
 * RT; the second create finds it already present. Reference-count those
 * owners so destroying one VRF does not remove the RT, and so a destroy of
 * an RT that is already gone does not hit the assert in
 * bgp_evpn_mh_config_ead_export_rt().
 */
PREDECL_HASH(bgp_nb_ead_rt_ref);

struct bgp_nb_ead_rt_ref {
	struct bgp_nb_ead_rt_ref_item item;
	char *rt;
	unsigned int refs;
};

static int bgp_nb_ead_rt_ref_cmp(const struct bgp_nb_ead_rt_ref *a,
				 const struct bgp_nb_ead_rt_ref *b)
{
	return strcmp(a->rt, b->rt);
}

static uint32_t bgp_nb_ead_rt_ref_hashfn(const struct bgp_nb_ead_rt_ref *a)
{
	uint32_t h = 5381;
	const char *s;

	for (s = a->rt; *s; s++)
		h = ((h << 5) + h) + (uint8_t)*s;
	return h;
}

DECLARE_HASH(bgp_nb_ead_rt_ref, struct bgp_nb_ead_rt_ref, item, bgp_nb_ead_rt_ref_cmp,
	     bgp_nb_ead_rt_ref_hashfn);

static struct bgp_nb_ead_rt_ref_head bgp_nb_ead_rt_refs;

static bool bgp_nb_ead_rt_in_list(struct ecommunity *ecom)
{
	struct listnode *node;
	struct ecommunity *exist;

	if (!bgp_mh_info || !bgp_mh_info->ead_es_export_rtl || !ecom)
		return false;
	for (ALL_LIST_ELEMENTS_RO(bgp_mh_info->ead_es_export_rtl, node, exist)) {
		if (ecommunity_match(exist, ecom))
			return true;
	}
	return false;
}

static void bgp_nb_ead_rt_ref_bump(const char *rt)
{
	struct bgp_nb_ead_rt_ref key = { .rt = (char *)rt };
	struct bgp_nb_ead_rt_ref *found;

	found = bgp_nb_ead_rt_ref_find(&bgp_nb_ead_rt_refs, &key);
	if (!found) {
		found = XCALLOC(MTYPE_TMP, sizeof(*found));
		found->rt = XSTRDUP(MTYPE_TMP, rt);
		bgp_nb_ead_rt_ref_add(&bgp_nb_ead_rt_refs, found);
	}
	found->refs++;
}

/* Remaining owners after this destroy. 0 means the global RT may go. */
static unsigned int bgp_nb_ead_rt_ref_drop(const char *rt)
{
	struct bgp_nb_ead_rt_ref key = { .rt = (char *)rt };
	struct bgp_nb_ead_rt_ref *found;

	found = bgp_nb_ead_rt_ref_find(&bgp_nb_ead_rt_refs, &key);
	if (!found)
		return 0;
	if (found->refs)
		found->refs--;
	if (found->refs)
		return found->refs;
	bgp_nb_ead_rt_ref_del(&bgp_nb_ead_rt_refs, found);
	XFREE(MTYPE_TMP, found->rt);
	XFREE(MTYPE_TMP, found);
	return 0;
}

int bgp_nb_evpn_ead_es_rt_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	struct ecommunity *ecom;

	switch (args->event) {
	case NB_EV_VALIDATE:
		bgp = nb_running_get_entry(args->dnode, NULL, false);
		if (!bgp)
			return NB_OK;
		if (!EVPN_ENABLED(bgp)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "This command is only supported under EVPN VRF");
			return NB_ERR_VALIDATION;
		}
		ecom = ecommunity_str2com(yang_dnode_get_string(args->dnode, NULL),
					  ECOMMUNITY_ROUTE_TARGET, 0);
		if (!ecom) {
			snprintfrr(args->errmsg, args->errmsg_len, "Malformed Route Target list");
			return NB_ERR_VALIDATION;
		}
		ecommunity_free(&ecom);
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp)
		return NB_ERR_NOT_FOUND;

	ecom = ecommunity_str2com(yang_dnode_get_string(args->dnode, NULL),
				  ECOMMUNITY_ROUTE_TARGET, 0);
	if (!ecom)
		return NB_ERR_VALIDATION;
	ecommunity_str(ecom);

	/*
	 * Another EVPN VRF already installed this RT. Count this owner and
	 * keep the single global entry.
	 */
	if (bgp_nb_ead_rt_in_list(ecom)) {
		bgp_nb_ead_rt_ref_bump(yang_dnode_get_string(args->dnode, NULL));
		ecommunity_free(&ecom);
		return NB_OK;
	}

	bgp_nb_ead_rt_ref_bump(yang_dnode_get_string(args->dnode, NULL));
	bgp_evpn_mh_config_ead_export_rt(bgp, ecom, false);
	return NB_OK;
}

int bgp_nb_evpn_ead_es_rt_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	struct ecommunity *ecom;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp)
		return NB_OK;

	ecom = ecommunity_str2com(yang_dnode_get_string(args->dnode, NULL),
				  ECOMMUNITY_ROUTE_TARGET, 0);
	if (!ecom)
		return NB_OK;
	ecommunity_str(ecom);

	/*
	 * Missing from the global list: nothing to delete. Do not call the
	 * MH helper, which asserts when the RT is absent. If other EVPN
	 * VRFs still own the RT, leave the single global entry in place.
	 */
	if (!bgp_nb_ead_rt_in_list(ecom)) {
		bgp_nb_ead_rt_ref_drop(yang_dnode_get_string(args->dnode, NULL));
		ecommunity_free(&ecom);
		return NB_OK;
	}
	if (bgp_nb_ead_rt_ref_drop(yang_dnode_get_string(args->dnode, NULL)) > 0) {
		ecommunity_free(&ecom);
		return NB_OK;
	}

	bgp_evpn_mh_config_ead_export_rt(bgp, ecom, true);
	ecommunity_free(&ecom);
	return NB_OK;
}

void bgp_nb_cli_show_evpn_ead_es_rt(struct vty *vty, const struct lyd_node *dnode,
				    bool show_defaults)
{
	vty_out(vty, "  ead-es-route-target export %s\n", yang_dnode_get_string(dnode, NULL));
}

/*
 * EVPN IP-VRF RD / route-target
 */
int bgp_nb_evpn_vrf_rd_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct prefix_rd prd;
	const char *rd_str;

	if (args->event == NB_EV_VALIDATE) {
		rd_str = yang_dnode_get_string(args->dnode, NULL);
		if (!str2prefix_rd(rd_str, &prd)) {
			snprintfrr(args->errmsg, args->errmsg_len, "Malformed Route Distinguisher");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_dnode_lookup_bgp(args->dnode);
	if (!bgp)
		return NB_ERR_NOT_FOUND;

	rd_str = yang_dnode_get_string(args->dnode, NULL);
	if (!str2prefix_rd(rd_str, &prd))
		return NB_ERR_VALIDATION;

	if (bgp_evpn_vrf_rd_matches_existing(bgp, &prd) &&
	    CHECK_FLAG(bgp->vrf_flags, BGP_VRF_RD_CFGD))
		return NB_OK;

	evpn_configure_vrf_rd(bgp, &prd, rd_str);
	return NB_OK;
}

int bgp_nb_evpn_vrf_rd_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_dnode_lookup_bgp(args->dnode);
	if (!bgp || !is_vrf_rd_configured(bgp))
		return NB_OK;

	evpn_unconfigure_vrf_rd(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_evpn_vrf_rd(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, "  rd %s\n", yang_dnode_get_string(dnode, NULL));
}

static bool bgp_nb_evpn_vrf_rt_is_import(const struct lyd_node *dnode)
{
	return strmatch(dnode->schema->name, "import-route-target");
}

/*
 * Hand a single route-target to EVPN through the batch interface.  EVPN
 * takes ownership of cfgd_rt.
 */
static void bgp_nb_evpn_vrf_rt_batch(struct bgp *bgp, struct bgp_evpn_cfgd_rt *cfgd_rt,
				     bool is_import, bool is_add)
{
	struct bgp_evpn_cfgd_rt_slu_head head;

	bgp_evpn_cfgd_rt_slu_init(&head);
	bgp_evpn_cfgd_rt_slu_add(&head, cfgd_rt);

	if (is_add && is_import)
		bgp_evpn_configure_import_rts_for_vrf_batch(bgp, &head);
	else if (is_add)
		bgp_evpn_configure_export_rts_for_vrf_batch(bgp, &head);
	else if (is_import)
		bgp_evpn_unconfigure_import_rts_for_vrf_batch(bgp, &head);
	else
		bgp_evpn_unconfigure_export_rts_for_vrf_batch(bgp, &head);

	bgp_evpn_cfgd_rt_slu_fini(&head);
}

/*
 * Parse an FRR CLI RT string. Wildcard import RTs are stored as "*:NN" in
 * YANG; classic CLI rewrites '*' to '0' before ecommunity_str2com().
 */
static enum bgp_evpn_autort_cfgd bgp_nb_evpn_autort_mode(const struct lyd_node *dnode);

static struct ecommunity *bgp_nb_evpn_vrf_rt_str2com(const char *rt_str, bool *is_wildcard)
{
	char buf[64];
	bool wildcard = false;

	if (is_wildcard)
		*is_wildcard = false;

	if (!rt_str || !rt_str[0])
		return NULL;

	if (rt_str[0] == '*') {
		if (strlen(rt_str) >= sizeof(buf))
			return NULL;
		strlcpy(buf, rt_str, sizeof(buf));
		buf[0] = '0';
		wildcard = true;
		rt_str = buf;
	}

	if (is_wildcard)
		*is_wildcard = wildcard;

	return ecommunity_str2com(rt_str, ECOMMUNITY_ROUTE_TARGET, 0);
}

/*
 * Re-apply VRF EVPN ip-vrf YANG (RD / RT / type-5 advertise) onto runtime.
 * YANG APPLY can race ahead of L3VNI bring-up; L3VNI add then auto-derives
 * RD/RT and never picks up the already-committed YANG leaves. Call after
 * L3VNI is attached so configured values win and type-5 is advertised.
 *
 * Resolve the l2vpn-evpn afi-safi by iterating children rather than an
 * identityref list-key predicate — lyd_find_xpath has been unreliable for
 * that form, which made reapply a silent no-op.
 */
void bgp_nb_evpn_vrf_yang_reapply(struct bgp *bgp)
{
	const struct lyd_node *bgp_dnode, *afs, *af, *ip_vrf, *child, *enable;
	struct prefix_rd prd;
	const char *rd_str;
	const char *af_name;
	struct ecommunity *ecom;
	bool is_wildcard;
	afi_t afi;
	safi_t safi;

	if (!bgp || !running_config || !running_config->dnode)
		return;

	/*
	 * Resolve the instance dnode by walking list keys — identityref
	 * xpath predicates for control-plane-protocol have been unreliable
	 * and made reapply a silent no-op (type-5 / RD never pushed after
	 * L3VNI attach).
	 */
	bgp_dnode = bgp_nb_find_instance_dnode(bgp);
	if (!bgp_dnode) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("%s: no YANG dnode for VRF %s", __func__, bgp->name_pretty);
		return;
	}

	afs = yang_dnode_get(bgp_dnode, "global/afi-safis");
	if (!afs) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("%s: no YANG afi-safis for VRF %s", __func__, bgp->name_pretty);
		return;
	}

	ip_vrf = NULL;
	LY_LIST_FOR (lyd_child(afs), af) {
		if (!strmatch(af->schema->name, "afi-safi"))
			continue;
		if (!yang_dnode_exists(af, "./afi-safi-name"))
			continue;
		af_name = yang_dnode_get_string(af, "./afi-safi-name");
		afi = AFI_UNSPEC;
		safi = SAFI_UNSPEC;
		yang_afi_safi_identity2value(af_name, &afi, &safi);
		if (afi != AFI_L2VPN || safi != SAFI_EVPN)
			continue;
		ip_vrf = yang_dnode_get(af, "l2vpn-evpn/ip-vrf");
		break;
	}
	if (!ip_vrf) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("%s: no YANG ip-vrf for VRF %s", __func__, bgp->name_pretty);
		return;
	}

	if (yang_dnode_exists(ip_vrf, "./rd")) {
		rd_str = yang_dnode_get_string(ip_vrf, "./rd");
		if (str2prefix_rd(rd_str, &prd) && (!CHECK_FLAG(bgp->vrf_flags, BGP_VRF_RD_CFGD) ||
						    !bgp_evpn_vrf_rd_matches_existing(bgp, &prd)))
			evpn_configure_vrf_rd(bgp, &prd, rd_str);
	}

	LY_LIST_FOR (lyd_child(ip_vrf), child) {
		if (strmatch(child->schema->name, "import-route-target")) {
			struct bgp_evpn_cfgd_rt *cfgd_rt;
			struct bgp_evpn_rt_config *rt_config;

			ecom = bgp_nb_evpn_vrf_rt_str2com(yang_dnode_get_string(child, NULL),
							  &is_wildcard);
			if (!ecom)
				continue;
			ecommunity_str(ecom);
			cfgd_rt = bgp_evpn_cfgd_rt_from_ecom(ecom, is_wildcard);
			ecommunity_free(&ecom);
			if (!cfgd_rt)
				continue;
			rt_config = bgp->vrf_route_target_config;
			if (bgp_evpn_cfgd_rt_slu_find(&rt_config->cfgd_import, cfgd_rt))
				bgp_evpn_cfgd_rt_free(cfgd_rt);
			else
				bgp_nb_evpn_vrf_rt_batch(bgp, cfgd_rt, true, true);
		} else if (strmatch(child->schema->name, "export-route-target")) {
			struct bgp_evpn_cfgd_rt *cfgd_rt;
			struct bgp_evpn_rt_config *rt_config;

			ecom = bgp_nb_evpn_vrf_rt_str2com(yang_dnode_get_string(child, NULL), NULL);
			if (!ecom)
				continue;
			ecommunity_str(ecom);
			cfgd_rt = bgp_evpn_cfgd_rt_from_ecom(ecom, false);
			ecommunity_free(&ecom);
			if (!cfgd_rt)
				continue;
			rt_config = bgp->vrf_route_target_config;
			if (bgp_evpn_cfgd_rt_slu_find(&rt_config->cfgd_export, cfgd_rt))
				bgp_evpn_cfgd_rt_free(cfgd_rt);
			else
				bgp_nb_evpn_vrf_rt_batch(bgp, cfgd_rt, false, true);
		} else if (strmatch(child->schema->name, "import-auto-route-target")) {
			bgp_evpn_configure_import_auto_rt_for_vrf(bgp,
								  bgp_nb_evpn_autort_mode(child));
		} else if (strmatch(child->schema->name, "export-auto-route-target")) {
			bgp_evpn_configure_export_auto_rt_for_vrf(bgp,
								  bgp_nb_evpn_autort_mode(child));
		}
	}

	enable = yang_dnode_get(ip_vrf, "./ipv4-unicast/enable");
	if (enable)
		bgp_nb_evpn_type5_apply(enable, bgp, false);
	enable = yang_dnode_get(ip_vrf, "./ipv6-unicast/enable");
	if (enable)
		bgp_nb_evpn_type5_apply(enable, bgp, false);
	enable = yang_dnode_get(ip_vrf, "./ipv4-vpn/enable");
	if (enable)
		bgp_nb_evpn_type5_apply(enable, bgp, false);
	enable = yang_dnode_get(ip_vrf, "./ipv6-vpn/enable");
	if (enable)
		bgp_nb_evpn_type5_apply(enable, bgp, false);

	if (bgp->l3vni)
		update_advertise_vrf_routes(bgp);
}

int bgp_nb_evpn_vrf_rt_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	struct ecommunity *ecom;
	struct bgp_evpn_cfgd_rt *cfgd_rt;
	struct bgp_evpn_rt_config *rt_config;
	const char *rt_str;
	bool is_import;
	bool is_wildcard;

	switch (args->event) {
	case NB_EV_VALIDATE:
		rt_str = yang_dnode_get_string(args->dnode, NULL);
		is_import = bgp_nb_evpn_vrf_rt_is_import(args->dnode);
		if (rt_str[0] == '*' && !is_import) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "Wildcard '*' only applicable for import");
			return NB_ERR_VALIDATION;
		}
		ecom = bgp_nb_evpn_vrf_rt_str2com(rt_str, NULL);
		if (!ecom) {
			snprintfrr(args->errmsg, args->errmsg_len, "Malformed Route Target list");
			return NB_ERR_VALIDATION;
		}
		ecommunity_free(&ecom);
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_dnode_lookup_bgp(args->dnode);
	if (!bgp)
		return NB_ERR_NOT_FOUND;

	is_import = bgp_nb_evpn_vrf_rt_is_import(args->dnode);
	rt_str = yang_dnode_get_string(args->dnode, NULL);
	ecom = bgp_nb_evpn_vrf_rt_str2com(rt_str, &is_wildcard);
	if (!ecom)
		return NB_ERR_VALIDATION;
	ecommunity_str(ecom);

	cfgd_rt = bgp_evpn_cfgd_rt_from_ecom(ecom, is_wildcard);
	ecommunity_free(&ecom);
	if (!cfgd_rt)
		return NB_ERR_VALIDATION;

	rt_config = bgp->vrf_route_target_config;
	if (is_import) {
		if (bgp_evpn_cfgd_rt_slu_find(&rt_config->cfgd_import, cfgd_rt)) {
			bgp_evpn_cfgd_rt_free(cfgd_rt);
			return NB_OK;
		}
		bgp_nb_evpn_vrf_rt_batch(bgp, cfgd_rt, true, true);
	} else {
		if (bgp_evpn_cfgd_rt_slu_find(&rt_config->cfgd_export, cfgd_rt)) {
			bgp_evpn_cfgd_rt_free(cfgd_rt);
			return NB_OK;
		}
		bgp_nb_evpn_vrf_rt_batch(bgp, cfgd_rt, false, true);
	}
	return NB_OK;
}

int bgp_nb_evpn_vrf_rt_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	struct ecommunity *ecom;
	struct bgp_evpn_cfgd_rt *cfgd_rt;
	bool is_import;
	bool is_wildcard;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_dnode_lookup_bgp(args->dnode);
	if (!bgp)
		return NB_OK;

	is_import = bgp_nb_evpn_vrf_rt_is_import(args->dnode);
	ecom = bgp_nb_evpn_vrf_rt_str2com(yang_dnode_get_string(args->dnode, NULL), &is_wildcard);
	if (!ecom)
		return NB_OK;
	ecommunity_str(ecom);

	cfgd_rt = bgp_evpn_cfgd_rt_from_ecom(ecom, is_wildcard);
	ecommunity_free(&ecom);
	if (!cfgd_rt)
		return NB_OK;

	bgp_nb_evpn_vrf_rt_batch(bgp, cfgd_rt, is_import, false);
	return NB_OK;
}

void bgp_nb_cli_show_evpn_vrf_rt_import(struct vty *vty, const struct lyd_node *dnode,
					bool show_defaults)
{
	vty_out(vty, "  route-target import %s\n", yang_dnode_get_string(dnode, NULL));
}

void bgp_nb_cli_show_evpn_vrf_rt_export(struct vty *vty, const struct lyd_node *dnode,
					bool show_defaults)
{
	vty_out(vty, "  route-target export %s\n", yang_dnode_get_string(dnode, NULL));
}

static bool bgp_nb_evpn_rt_auto_is_import(const struct lyd_node *dnode)
{
	return strmatch(dnode->schema->name, "import-auto-route-target");
}

static enum bgp_evpn_autort_cfgd bgp_nb_evpn_autort_mode(const struct lyd_node *dnode)
{
	const char *mode = yang_dnode_get_string(dnode, NULL);

	if (strmatch(mode, "add-always"))
		return BGP_EVPN_AUTORT_ADD_ALWAYS;
	if (strmatch(mode, "add-never"))
		return BGP_EVPN_AUTORT_ADD_NEVER;
	return BGP_EVPN_AUTORT_ADD_IF_NO_MANUAL;
}

int bgp_nb_evpn_vrf_rt_auto_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	enum bgp_evpn_autort_cfgd autort;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp)
		return NB_ERR_NOT_FOUND;

	autort = bgp_nb_evpn_autort_mode(args->dnode);
	if (bgp_nb_evpn_rt_auto_is_import(args->dnode))
		bgp_evpn_configure_import_auto_rt_for_vrf(bgp, autort);
	else
		bgp_evpn_configure_export_auto_rt_for_vrf(bgp, autort);
	return NB_OK;
}

int bgp_nb_evpn_vrf_rt_auto_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp)
		return NB_OK;

	if (bgp_nb_evpn_rt_auto_is_import(args->dnode))
		bgp_evpn_unconfigure_import_auto_rt_for_vrf(bgp);
	else
		bgp_evpn_unconfigure_export_auto_rt_for_vrf(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_evpn_vrf_rt_auto(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults)
{
	vty_out(vty, "  auto-route-target %s %s\n",
		bgp_nb_evpn_rt_auto_is_import(dnode) ? "import" : "export",
		yang_dnode_get_string(dnode, NULL));
}

/*
 * EVPN VNI list and per-VNI knobs
 */
static struct bgp *bgp_nb_evpn_vni_underlay(const struct lyd_node *dnode)
{
	const struct lyd_node *af;

	af = yang_dnode_get_parent(dnode, "afi-safi");
	/* Never abort: VALIDATE runs before BGP APPLY during config load. */
	if (af) {
		struct bgp *bgp = nb_running_get_entry(af, NULL, false);

		if (bgp)
			return bgp;
	}
	return bgp_nb_dnode_lookup_bgp(dnode);
}

int bgp_nb_evpn_vni_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	struct bgpevpn *vpn;
	vni_t vni;

	switch (args->event) {
	case NB_EV_VALIDATE:
		/*
		 * L3VNI conflict check does not need struct bgp. Requiring a
		 * running BGP entry here aborts during integrated config load
		 * when VALIDATE runs before any APPLY.
		 */
		vni = yang_dnode_get_uint32(args->dnode, "./vni");
		if (bgp_evpn_lookup_l3vni_l2vni_table(vni)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "Failed to create L2VNI %u, it is configured as L3VNI", vni);
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_evpn_vni_underlay(args->dnode);
	if (!bgp)
		return NB_ERR_NOT_FOUND;

	vni = yang_dnode_get_uint32(args->dnode, "./vni");
	vpn = evpn_create_update_vni(bgp, vni);
	if (!vpn)
		return NB_ERR_RESOURCE;

	nb_running_set_entry(args->dnode, vpn);
	return NB_OK;
}

int bgp_nb_evpn_vni_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	struct bgpevpn *vpn;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_evpn_vni_underlay(args->dnode);
	vpn = nb_running_unset_entry(args->dnode);
	if (!bgp || !vpn)
		return NB_OK;

	evpn_delete_vni(bgp, vpn);
	return NB_OK;
}

void bgp_nb_cli_show_evpn_vni(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, "  vni %u\n", yang_dnode_get_uint32(dnode, "./vni"));
}

void bgp_nb_cli_show_evpn_vni_end(struct vty *vty, const struct lyd_node *dnode)
{
	vty_out(vty, "  exit-vni\n");
}

int bgp_nb_evpn_vni_rd_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct bgpevpn *vpn;
	struct prefix_rd prd;
	const char *rd_str;

	if (args->event == NB_EV_VALIDATE) {
		rd_str = yang_dnode_get_string(args->dnode, NULL);
		if (!str2prefix_rd(rd_str, &prd)) {
			snprintfrr(args->errmsg, args->errmsg_len, "Malformed Route Distinguisher");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	vpn = nb_running_get_entry(args->dnode, NULL, true);
	bgp = bgp_nb_evpn_vni_underlay(args->dnode);
	if (!vpn || !bgp)
		return NB_ERR_NOT_FOUND;

	rd_str = yang_dnode_get_string(args->dnode, NULL);
	if (!str2prefix_rd(rd_str, &prd))
		return NB_ERR_VALIDATION;
	if (bgp_evpn_rd_matches_existing(vpn, &prd))
		return NB_OK;

	evpn_configure_rd(bgp, vpn, &prd, rd_str);
	return NB_OK;
}

int bgp_nb_evpn_vni_rd_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	struct bgpevpn *vpn;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	vpn = nb_running_get_entry(args->dnode, NULL, true);
	bgp = bgp_nb_evpn_vni_underlay(args->dnode);
	if (!vpn || !bgp || !is_rd_configured(vpn))
		return NB_OK;

	evpn_unconfigure_rd(bgp, vpn);
	return NB_OK;
}

void bgp_nb_cli_show_evpn_vni_rd(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, "   rd %s\n", yang_dnode_get_string(dnode, NULL));
}

static bool bgp_nb_evpn_vni_rt_is_import(const struct lyd_node *dnode)
{
	return strmatch(dnode->schema->name, "import-route-target");
}

int bgp_nb_evpn_vni_rt_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	struct bgpevpn *vpn;
	struct ecommunity *ecom;
	struct bgp_evpn_cfgd_rt *cfgd_rt;
	const char *rt_str;
	bool is_import;
	bool is_wildcard;

	switch (args->event) {
	case NB_EV_VALIDATE:
		rt_str = yang_dnode_get_string(args->dnode, NULL);
		if (rt_str[0] == '*' && !bgp_nb_evpn_vni_rt_is_import(args->dnode)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "Wildcard '*' only applicable for import");
			return NB_ERR_VALIDATION;
		}
		ecom = bgp_nb_evpn_vrf_rt_str2com(rt_str, NULL);
		if (!ecom) {
			snprintfrr(args->errmsg, args->errmsg_len, "Malformed Route Target list");
			return NB_ERR_VALIDATION;
		}
		ecommunity_free(&ecom);
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	vpn = nb_running_get_entry(args->dnode, NULL, true);
	bgp = bgp_nb_evpn_vni_underlay(args->dnode);
	if (!vpn || !bgp)
		return NB_ERR_NOT_FOUND;

	is_import = bgp_nb_evpn_vni_rt_is_import(args->dnode);
	ecom = bgp_nb_evpn_vrf_rt_str2com(yang_dnode_get_string(args->dnode, NULL), &is_wildcard);
	if (!ecom)
		return NB_ERR_VALIDATION;
	ecommunity_str(ecom);

	cfgd_rt = bgp_evpn_cfgd_rt_from_ecom(ecom, is_wildcard);
	ecommunity_free(&ecom);
	if (!cfgd_rt)
		return NB_ERR_VALIDATION;

	if (is_import) {
		if (bgp_evpn_cfgd_rt_slu_find(&vpn->rt_config->cfgd_import, cfgd_rt)) {
			bgp_evpn_cfgd_rt_free(cfgd_rt);
			return NB_OK;
		}
		evpn_configure_import_rt_for_l2vni(bgp, vpn, cfgd_rt);
	} else {
		if (bgp_evpn_cfgd_rt_slu_find(&vpn->rt_config->cfgd_export, cfgd_rt)) {
			bgp_evpn_cfgd_rt_free(cfgd_rt);
			return NB_OK;
		}
		evpn_configure_export_rt_for_l2vni(bgp, vpn, cfgd_rt);
	}
	return NB_OK;
}

int bgp_nb_evpn_vni_rt_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	struct bgpevpn *vpn;
	struct ecommunity *ecom;
	struct bgp_evpn_cfgd_rt *cfgd_rt;
	bool is_import;
	bool is_wildcard;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	vpn = nb_running_get_entry(args->dnode, NULL, true);
	bgp = bgp_nb_evpn_vni_underlay(args->dnode);
	if (!vpn || !bgp)
		return NB_OK;

	is_import = bgp_nb_evpn_vni_rt_is_import(args->dnode);
	ecom = bgp_nb_evpn_vrf_rt_str2com(yang_dnode_get_string(args->dnode, NULL), &is_wildcard);
	if (!ecom)
		return NB_OK;
	ecommunity_str(ecom);

	cfgd_rt = bgp_evpn_cfgd_rt_from_ecom(ecom, is_wildcard);
	ecommunity_free(&ecom);
	if (!cfgd_rt)
		return NB_OK;

	if (is_import)
		evpn_unconfigure_import_rt_for_l2vni(bgp, vpn, cfgd_rt);
	else
		evpn_unconfigure_export_rt_for_l2vni(bgp, vpn, cfgd_rt);
	bgp_evpn_cfgd_rt_free(cfgd_rt);
	return NB_OK;
}

void bgp_nb_cli_show_evpn_vni_rt_import(struct vty *vty, const struct lyd_node *dnode,
					bool show_defaults)
{
	vty_out(vty, "   route-target import %s\n", yang_dnode_get_string(dnode, NULL));
}

void bgp_nb_cli_show_evpn_vni_rt_export(struct vty *vty, const struct lyd_node *dnode,
					bool show_defaults)
{
	vty_out(vty, "   route-target export %s\n", yang_dnode_get_string(dnode, NULL));
}

int bgp_nb_evpn_vni_rt_auto_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct bgpevpn *vpn;
	enum bgp_evpn_autort_cfgd autort;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	vpn = nb_running_get_entry(args->dnode, NULL, true);
	bgp = bgp_nb_evpn_vni_underlay(args->dnode);
	if (!vpn || !bgp)
		return NB_ERR_NOT_FOUND;

	autort = bgp_nb_evpn_autort_mode(args->dnode);
	if (bgp_nb_evpn_rt_auto_is_import(args->dnode))
		evpn_configure_import_auto_rt_for_l2vni(bgp, vpn, autort);
	else
		evpn_configure_export_auto_rt_for_l2vni(bgp, vpn, autort);
	return NB_OK;
}

int bgp_nb_evpn_vni_rt_auto_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	struct bgpevpn *vpn;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	vpn = nb_running_get_entry(args->dnode, NULL, true);
	bgp = bgp_nb_evpn_vni_underlay(args->dnode);
	if (!vpn || !bgp)
		return NB_OK;

	if (bgp_nb_evpn_rt_auto_is_import(args->dnode))
		evpn_unconfigure_import_auto_rt_for_l2vni(bgp, vpn);
	else
		evpn_unconfigure_export_auto_rt_for_l2vni(bgp, vpn);
	return NB_OK;
}

void bgp_nb_cli_show_evpn_vni_rt_auto(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults)
{
	vty_out(vty, "   auto-route-target %s %s\n",
		bgp_nb_evpn_rt_auto_is_import(dnode) ? "import" : "export",
		yang_dnode_get_string(dnode, NULL));
}

int bgp_nb_evpn_vni_advertise_default_gw_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct bgpevpn *vpn;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	vpn = nb_running_get_entry(args->dnode, NULL, true);
	bgp = bgp_nb_evpn_vni_underlay(args->dnode);
	if (!vpn || !bgp)
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL))
		evpn_set_advertise_default_gw(bgp, vpn);
	else
		evpn_unset_advertise_default_gw(bgp, vpn);
	return NB_OK;
}

int bgp_nb_evpn_vni_advertise_default_gw_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	struct bgpevpn *vpn;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	vpn = nb_running_get_entry(args->dnode, NULL, true);
	bgp = bgp_nb_evpn_vni_underlay(args->dnode);
	if (!vpn || !bgp)
		return NB_OK;

	evpn_unset_advertise_default_gw(bgp, vpn);
	return NB_OK;
}

void bgp_nb_cli_show_evpn_vni_advertise_default_gw(struct vty *vty, const struct lyd_node *dnode,
						   bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "   advertise-default-gw\n");
}

int bgp_nb_evpn_vni_advertise_svi_ip_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct bgpevpn *vpn;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	vpn = nb_running_get_entry(args->dnode, NULL, true);
	bgp = bgp_nb_evpn_vni_underlay(args->dnode);
	if (!vpn || !bgp)
		return NB_ERR_NOT_FOUND;

	evpn_set_advertise_svi_macip(bgp, vpn, yang_dnode_get_bool(args->dnode, NULL) ? 1 : 0);
	return NB_OK;
}

int bgp_nb_evpn_vni_advertise_svi_ip_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	struct bgpevpn *vpn;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	vpn = nb_running_get_entry(args->dnode, NULL, true);
	bgp = bgp_nb_evpn_vni_underlay(args->dnode);
	if (!vpn || !bgp)
		return NB_OK;

	evpn_set_advertise_svi_macip(bgp, vpn, 0);
	return NB_OK;
}

void bgp_nb_cli_show_evpn_vni_advertise_svi_ip(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "   advertise-svi-ip\n");
}

int bgp_nb_evpn_vni_advertise_subnet_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct bgpevpn *vpn;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	vpn = nb_running_get_entry(args->dnode, NULL, true);
	bgp = bgp_nb_evpn_vni_underlay(args->dnode);
	if (!vpn || !bgp)
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL))
		evpn_set_advertise_subnet(bgp, vpn);
	else
		evpn_unset_advertise_subnet(bgp, vpn);
	return NB_OK;
}

int bgp_nb_evpn_vni_advertise_subnet_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	struct bgpevpn *vpn;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	vpn = nb_running_get_entry(args->dnode, NULL, true);
	bgp = bgp_nb_evpn_vni_underlay(args->dnode);
	if (!vpn || !bgp)
		return NB_OK;

	evpn_unset_advertise_subnet(bgp, vpn);
	return NB_OK;
}

void bgp_nb_cli_show_evpn_vni_advertise_subnet(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "   advertise-subnet\n");
}

int bgp_nb_evpn_vni_flooding_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct bgpevpn *vpn;
	const char *val;
	enum vxlan_flood_control flood_ctrl;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	vpn = nb_running_get_entry(args->dnode, NULL, true);
	bgp = bgp_nb_evpn_vni_underlay(args->dnode);
	if (!vpn || !bgp)
		return NB_ERR_NOT_FOUND;

	val = yang_dnode_get_string(args->dnode, NULL);
	if (strmatch(val, "disable"))
		flood_ctrl = VXLAN_FLOOD_DISABLED;
	else if (strmatch(val, "head-end-replication"))
		flood_ctrl = VXLAN_FLOOD_HEAD_END_REPL;
	else
		flood_ctrl = VXLAN_FLOOD_INHERIT_GLOBAL;

	if (vpn->vxlan_flood_ctrl == flood_ctrl)
		return NB_OK;

	vpn->vxlan_flood_ctrl = flood_ctrl;
	bgp_evpn_flood_control_change(bgp);
	return NB_OK;
}

int bgp_nb_evpn_vni_flooding_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	struct bgpevpn *vpn;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	vpn = nb_running_get_entry(args->dnode, NULL, true);
	bgp = bgp_nb_evpn_vni_underlay(args->dnode);
	if (!vpn || !bgp)
		return NB_OK;

	if (vpn->vxlan_flood_ctrl == VXLAN_FLOOD_INHERIT_GLOBAL)
		return NB_OK;

	vpn->vxlan_flood_ctrl = VXLAN_FLOOD_INHERIT_GLOBAL;
	bgp_evpn_flood_control_change(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_evpn_vni_flooding(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults)
{
	const char *val = yang_dnode_get_string(dnode, NULL);

	if (strmatch(val, "inherit-global") && !show_defaults)
		return;
	if (strmatch(val, "disable"))
		vty_out(vty, "   flooding disable\n");
	else if (strmatch(val, "head-end-replication"))
		vty_out(vty, "   flooding head-end-replication\n");
}

/*
 * AF-level import|export vpn
 */
static int bgp_nb_vpn_imexport_validate(struct bgp *bgp, afi_t afi, safi_t safi, bool enable,
					char *errmsg, size_t errmsg_len)
{
	if (bgp->inst_type != BGP_INSTANCE_TYPE_VRF && bgp->inst_type != BGP_INSTANCE_TYPE_DEFAULT) {
		snprintfrr(errmsg, errmsg_len,
			   "import|export vpn valid only for bgp vrf or default instance");
		return NB_ERR_VALIDATION;
	}

	if (safi != SAFI_UNICAST || (afi != AFI_IP && afi != AFI_IP6)) {
		snprintfrr(errmsg, errmsg_len,
			   "import|export vpn valid only for unicast ipv4|ipv6");
		return NB_ERR_VALIDATION;
	}

	if (enable && (CHECK_FLAG(bgp->af_flags[afi][safi], BGP_CONFIG_VRF_TO_VRF_IMPORT) ||
		       CHECK_FLAG(bgp->af_flags[afi][safi], BGP_CONFIG_VRF_TO_VRF_EXPORT))) {
		snprintfrr(errmsg, errmsg_len,
			   "Please unconfigure import vrf commands before using vpn commands");
		return NB_ERR_VALIDATION;
	}

	return NB_OK;
}

static int bgp_nb_vpn_imexport_apply(struct bgp *bgp, afi_t afi, safi_t safi, bool enable,
				     int flag, enum vpn_policy_direction dir)
{
	struct bgp *bgp_default = bgp_get_default();
	int previous_state = CHECK_FLAG(bgp->af_flags[afi][safi], flag);

	if (enable) {
		SET_FLAG(bgp->af_flags[afi][safi], flag);
		if (!previous_state)
			vpn_leak_postchange(dir, afi, bgp_default, bgp);
	} else {
		if (previous_state)
			vpn_leak_prechange(dir, afi, bgp_default, bgp);
		UNSET_FLAG(bgp->af_flags[afi][safi], flag);
		if (previous_state && bgp_default &&
		    !CHECK_FLAG(bgp_default->af_flags[afi][SAFI_MPLS_VPN],
				BGP_VPNVX_RETAIN_ROUTE_TARGET_ALL))
			vpn_leak_no_retain(bgp, bgp_default, afi);
	}

	hook_call(bgp_snmp_init_stats, bgp);
	return NB_OK;
}

int bgp_nb_vpn_import_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	bool enable;

	enable = yang_dnode_get_bool(args->dnode, NULL);

	switch (args->event) {
	case NB_EV_VALIDATE:
		bgp = nb_running_get_entry(args->dnode, NULL, false);
		if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
			return NB_OK;
		return bgp_nb_vpn_imexport_validate(bgp, afi, safi, enable, args->errmsg,
						    args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	return bgp_nb_vpn_imexport_apply(bgp, afi, safi, enable, BGP_CONFIG_MPLSVPN_TO_VRF_IMPORT,
					 BGP_VPN_POLICY_DIR_FROMVPN);
}

int bgp_nb_vpn_import_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	return bgp_nb_vpn_imexport_apply(bgp, afi, safi, false, BGP_CONFIG_MPLSVPN_TO_VRF_IMPORT,
					 BGP_VPN_POLICY_DIR_FROMVPN);
}

void bgp_nb_cli_show_vpn_import(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL) || show_defaults)
		vty_out(vty, "  import vpn\n");
}

int bgp_nb_vpn_export_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	bool enable;

	enable = yang_dnode_get_bool(args->dnode, NULL);

	switch (args->event) {
	case NB_EV_VALIDATE:
		bgp = nb_running_get_entry(args->dnode, NULL, false);
		if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
			return NB_OK;
		return bgp_nb_vpn_imexport_validate(bgp, afi, safi, enable, args->errmsg,
						    args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	return bgp_nb_vpn_imexport_apply(bgp, afi, safi, enable, BGP_CONFIG_VRF_TO_MPLSVPN_EXPORT,
					 BGP_VPN_POLICY_DIR_TOVPN);
}

int bgp_nb_vpn_export_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	return bgp_nb_vpn_imexport_apply(bgp, afi, safi, false, BGP_CONFIG_VRF_TO_MPLSVPN_EXPORT,
					 BGP_VPN_POLICY_DIR_TOVPN);
}

void bgp_nb_cli_show_vpn_export(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL) || show_defaults)
		vty_out(vty, "  export vpn\n");
}

/*
 * AF-level route-map vpn import|export
 */
static int bgp_nb_vpn_rmap_validate(struct bgp *bgp, afi_t afi, safi_t safi, char *errmsg,
				    size_t errmsg_len)
{
	if (safi != SAFI_UNICAST || (afi != AFI_IP && afi != AFI_IP6)) {
		snprintfrr(errmsg, errmsg_len, "route-map vpn valid only for unicast ipv4|ipv6");
		return NB_ERR_VALIDATION;
	}

	if (CHECK_FLAG(bgp->af_flags[afi][safi], BGP_CONFIG_VRF_TO_VRF_IMPORT) ||
	    CHECK_FLAG(bgp->af_flags[afi][safi], BGP_CONFIG_VRF_TO_VRF_EXPORT)) {
		snprintfrr(errmsg, errmsg_len,
			   "Please unconfigure import vrf commands before using vpn commands");
		return NB_ERR_VALIDATION;
	}

	return NB_OK;
}

static int bgp_nb_vpn_rmap_apply(struct bgp *bgp, afi_t afi, enum vpn_policy_direction dir,
				 const char *rmap_name)
{
	vpn_leak_prechange(dir, afi, bgp_get_default(), bgp);

	if (bgp->vpn_policy[afi].rmap_name[dir])
		XFREE(MTYPE_ROUTE_MAP_NAME, bgp->vpn_policy[afi].rmap_name[dir]);

	if (rmap_name) {
		bgp->vpn_policy[afi].rmap_name[dir] = XSTRDUP(MTYPE_ROUTE_MAP_NAME, rmap_name);
		bgp->vpn_policy[afi].rmap[dir] = route_map_lookup_by_name(rmap_name);
	} else {
		bgp->vpn_policy[afi].rmap_name[dir] = NULL;
		bgp->vpn_policy[afi].rmap[dir] = NULL;
	}

	vpn_leak_postchange(dir, afi, bgp_get_default(), bgp);
	return NB_OK;
}

int bgp_nb_vpn_rmap_import_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	switch (args->event) {
	case NB_EV_VALIDATE:
		bgp = nb_running_get_entry(args->dnode, NULL, false);
		if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
			return NB_OK;
		if (yang_dnode_exists(args->dnode, "../vrf-rmap-import")) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "route-map vpn import conflicts with import vrf route-map");
			return NB_ERR_VALIDATION;
		}
		return bgp_nb_vpn_rmap_validate(bgp, afi, safi, args->errmsg, args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	return bgp_nb_vpn_rmap_apply(bgp, afi, BGP_VPN_POLICY_DIR_FROMVPN,
				     yang_dnode_get_string(args->dnode, NULL));
}

int bgp_nb_vpn_rmap_import_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	return bgp_nb_vpn_rmap_apply(bgp, afi, BGP_VPN_POLICY_DIR_FROMVPN, NULL);
}

void bgp_nb_cli_show_vpn_rmap_import(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults)
{
	vty_out(vty, "  route-map vpn import %s\n", yang_dnode_get_string(dnode, NULL));
}

int bgp_nb_vpn_rmap_export_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	switch (args->event) {
	case NB_EV_VALIDATE:
		bgp = nb_running_get_entry(args->dnode, NULL, false);
		if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
			return NB_OK;
		return bgp_nb_vpn_rmap_validate(bgp, afi, safi, args->errmsg, args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	return bgp_nb_vpn_rmap_apply(bgp, afi, BGP_VPN_POLICY_DIR_TOVPN,
				     yang_dnode_get_string(args->dnode, NULL));
}

int bgp_nb_vpn_rmap_export_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	return bgp_nb_vpn_rmap_apply(bgp, afi, BGP_VPN_POLICY_DIR_TOVPN, NULL);
}

void bgp_nb_cli_show_vpn_rmap_export(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults)
{
	vty_out(vty, "  route-map vpn export %s\n", yang_dnode_get_string(dnode, NULL));
}

/*
 * AF-level rd vpn export
 */
int bgp_nb_vpn_rd_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	struct prefix_rd prd;
	const char *rd_str;

	rd_str = yang_dnode_get_string(args->dnode, NULL);

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (!str2prefix_rd(rd_str, &prd)) {
			snprintfrr(args->errmsg, args->errmsg_len, "Malformed rd");
			return NB_ERR_VALIDATION;
		}
		bgp = nb_running_get_entry(args->dnode, NULL, false);
		if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
			return NB_OK;
		return bgp_nb_vpn_rmap_validate(bgp, afi, safi, args->errmsg, args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	if (!str2prefix_rd(rd_str, &prd))
		return NB_ERR_VALIDATION;

	if (bgp->vpn_policy[afi].tovpn_rd_pretty &&
	    strmatch(rd_str, bgp->vpn_policy[afi].tovpn_rd_pretty))
		return NB_OK;

	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);

	hook_call(bgp_route_distinguisher_update, bgp, afi, true);
	if (bgp->vpn_policy[afi].tovpn_rd_pretty)
		XFREE(MTYPE_BGP_NAME, bgp->vpn_policy[afi].tovpn_rd_pretty);
	bgp->vpn_policy[afi].tovpn_rd_pretty = XSTRDUP(MTYPE_BGP_NAME, rd_str);
	bgp->vpn_policy[afi].tovpn_rd = prd;
	SET_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_RD_SET);
	SET_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_RD_CLI_SET);
	hook_call(bgp_route_distinguisher_update, bgp, afi, false);

	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);
	return NB_OK;
}

int bgp_nb_vpn_rd_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	if (!bgp->vpn_policy[afi].tovpn_rd_pretty)
		return NB_OK;

	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);

	hook_call(bgp_route_distinguisher_update, bgp, afi, true);
	XFREE(MTYPE_BGP_NAME, bgp->vpn_policy[afi].tovpn_rd_pretty);
	bgp->vpn_policy[afi].tovpn_rd_pretty = NULL;
	UNSET_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_RD_SET);
	UNSET_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_RD_CLI_SET);
	hook_call(bgp_route_distinguisher_update, bgp, afi, false);

	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);
	return NB_OK;
}

void bgp_nb_cli_show_vpn_rd(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, "  rd vpn export %s\n", yang_dnode_get_string(dnode, NULL));
}

/*
 * AF-level label vpn export / allocation-mode
 */
static void bgp_nb_vpn_label_release_current(struct bgp *bgp, afi_t afi)
{
	if (CHECK_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_LABEL_MANUAL_REG)) {
		bgp_zebra_release_label_range(bgp->vpn_policy[afi].tovpn_label,
					      bgp->vpn_policy[afi].tovpn_label);
		UNSET_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_LABEL_MANUAL_REG);
	} else if (CHECK_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_LABEL_AUTO)) {
		bgp_vpn_release_label(bgp, afi, false);
	}
}

static int bgp_nb_vpn_label_clear(struct bgp *bgp, afi_t afi)
{
	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);
	bgp_nb_vpn_label_release_current(bgp, afi);
	UNSET_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_LABEL_AUTO);
	bgp->vpn_policy[afi].tovpn_label = MPLS_LABEL_NONE;
	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);
	hook_call(bgp_snmp_update_last_changed, bgp);
	return NB_OK;
}

int bgp_nb_vpn_label_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	mpls_label_t label;

	label = yang_dnode_get_uint32(args->dnode, NULL);

	switch (args->event) {
	case NB_EV_VALIDATE:
		bgp = nb_running_get_entry(args->dnode, NULL, false);
		if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
			return NB_OK;
		return bgp_nb_vpn_rmap_validate(bgp, afi, safi, args->errmsg, args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	if (!CHECK_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_LABEL_AUTO) &&
	    label == bgp->vpn_policy[afi].tovpn_label)
		return NB_OK;

	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);
	bgp_nb_vpn_label_release_current(bgp, afi);

	bgp->vpn_policy[afi].tovpn_label = label;
	UNSET_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_LABEL_AUTO);
	if (bgp->vpn_policy[afi].tovpn_label >= MPLS_LABEL_UNRESERVED_MIN &&
	    bgp_zebra_request_label_range(bgp->vpn_policy[afi].tovpn_label, 1, false))
		SET_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_LABEL_MANUAL_REG);

	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);
	hook_call(bgp_snmp_update_last_changed, bgp);
	return NB_OK;
}

int bgp_nb_vpn_label_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	/* Auto mode uses label-auto; leave it alone if active. */
	if (CHECK_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_LABEL_AUTO))
		return NB_OK;

	if (bgp->vpn_policy[afi].tovpn_label == MPLS_LABEL_NONE)
		return NB_OK;

	return bgp_nb_vpn_label_clear(bgp, afi);
}

void bgp_nb_cli_show_vpn_label(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, "  label vpn export %u\n", yang_dnode_get_uint32(dnode, NULL));
}

int bgp_nb_vpn_label_auto_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	bool enable;

	enable = yang_dnode_get_bool(args->dnode, NULL);

	switch (args->event) {
	case NB_EV_VALIDATE:
		bgp = nb_running_get_entry(args->dnode, NULL, false);
		if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
			return NB_OK;
		return bgp_nb_vpn_rmap_validate(bgp, afi, safi, args->errmsg, args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	if (enable) {
		if (CHECK_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_LABEL_AUTO))
			return NB_OK;

		vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);
		bgp_nb_vpn_label_release_current(bgp, afi);
		SET_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_LABEL_AUTO);
		bgp->vpn_policy[afi].tovpn_label = MPLS_LABEL_NONE;
		vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);
		hook_call(bgp_snmp_update_last_changed, bgp);
		return NB_OK;
	}

	if (!CHECK_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_LABEL_AUTO))
		return NB_OK;

	return bgp_nb_vpn_label_clear(bgp, afi);
}

int bgp_nb_vpn_label_auto_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	if (!CHECK_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_LABEL_AUTO))
		return NB_OK;

	return bgp_nb_vpn_label_clear(bgp, afi);
}

void bgp_nb_cli_show_vpn_label_auto(struct vty *vty, const struct lyd_node *dnode,
				    bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL) || show_defaults)
		vty_out(vty, "  label vpn export auto\n");
}

int bgp_nb_vpn_label_alloc_mode_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	const char *mode;
	bool new_per_nexthop;
	bool old_per_nexthop;

	mode = yang_dnode_get_string(args->dnode, NULL);
	new_per_nexthop = strmatch(mode, "per-nexthop");

	switch (args->event) {
	case NB_EV_VALIDATE:
		bgp = nb_running_get_entry(args->dnode, NULL, false);
		if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
			return NB_OK;
		return bgp_nb_vpn_rmap_validate(bgp, afi, safi, args->errmsg, args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	old_per_nexthop = !!CHECK_FLAG(bgp->vpn_policy[afi].flags,
				       BGP_VPN_POLICY_TOVPN_LABEL_PER_NEXTHOP);
	if (old_per_nexthop == new_per_nexthop)
		return NB_OK;

	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);
	if (new_per_nexthop)
		SET_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_LABEL_PER_NEXTHOP);
	else
		UNSET_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_LABEL_PER_NEXTHOP);
	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);
	hook_call(bgp_snmp_update_last_changed, bgp);
	return NB_OK;
}

int bgp_nb_vpn_label_alloc_mode_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	if (!CHECK_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_LABEL_PER_NEXTHOP))
		return NB_OK;

	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);
	UNSET_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_LABEL_PER_NEXTHOP);
	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);
	hook_call(bgp_snmp_update_last_changed, bgp);
	return NB_OK;
}

void bgp_nb_cli_show_vpn_label_alloc_mode(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults)
{
	const char *mode = yang_dnode_get_string(dnode, NULL);

	if (strmatch(mode, "per-nexthop") || show_defaults)
		vty_out(vty, "  label vpn export allocation-mode %s\n", mode);
}

/*
 * AF-level nexthop vpn export
 */
int bgp_nb_vpn_nexthop_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	union sockunion su;
	struct prefix p;
	const char *nh_str;

	nh_str = yang_dnode_get_string(args->dnode, NULL);

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (str2sockunion(nh_str, &su) < 0 || !sockunion2hostprefix(&su, &p)) {
			snprintfrr(args->errmsg, args->errmsg_len, "Invalid nexthop");
			return NB_ERR_VALIDATION;
		}
		bgp = nb_running_get_entry(args->dnode, NULL, false);
		if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
			return NB_OK;
		return bgp_nb_vpn_rmap_validate(bgp, afi, safi, args->errmsg, args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	if (str2sockunion(nh_str, &su) < 0 || !sockunion2hostprefix(&su, &p))
		return NB_ERR_VALIDATION;

	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);
	bgp->vpn_policy[afi].tovpn_nexthop = p;
	SET_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_NEXTHOP_SET);
	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);
	return NB_OK;
}

int bgp_nb_vpn_nexthop_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	if (!CHECK_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_NEXTHOP_SET))
		return NB_OK;

	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);
	UNSET_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_NEXTHOP_SET);
	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);
	return NB_OK;
}

void bgp_nb_cli_show_vpn_nexthop(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, "  nexthop vpn export %s\n", yang_dnode_get_string(dnode, NULL));
}

/*
 * AF-level rt vpn import|export|both
 */
static int bgp_nb_vpn_rt_parse(const char *rt_str, struct ecommunity **ecom, char *errmsg,
			       size_t errmsg_len)
{
	*ecom = ecommunity_str2com(rt_str, ECOMMUNITY_ROUTE_TARGET, 0);
	if (!*ecom) {
		if (errmsg)
			snprintfrr(errmsg, errmsg_len, "Malformed community-list value");
		return NB_ERR_VALIDATION;
	}
	return NB_OK;
}

static int bgp_nb_vpn_rt_add(struct bgp *bgp, afi_t afi, enum vpn_policy_direction dir,
			     struct ecommunity *add)
{
	vpn_leak_prechange(dir, afi, bgp_get_default(), bgp);

	if (bgp->vpn_policy[afi].rtlist[dir]) {
		ecommunity_merge(bgp->vpn_policy[afi].rtlist[dir], add);
		ecommunity_free(&add);
	} else
		bgp->vpn_policy[afi].rtlist[dir] = add;

	vpn_leak_postchange(dir, afi, bgp_get_default(), bgp);
	return NB_OK;
}

static int bgp_nb_vpn_rt_del(struct bgp *bgp, afi_t afi, enum vpn_policy_direction dir,
			     struct ecommunity *tmp)
{
	struct ecommunity_val eval;

	if (!bgp->vpn_policy[afi].rtlist[dir] || !tmp || !tmp->size)
		return NB_OK;

	memcpy(eval.val, tmp->val, tmp->unit_size);

	vpn_leak_prechange(dir, afi, bgp_get_default(), bgp);

	ecommunity_del_val(bgp->vpn_policy[afi].rtlist[dir], &eval);
	if (!bgp->vpn_policy[afi].rtlist[dir]->size)
		ecommunity_free(&bgp->vpn_policy[afi].rtlist[dir]);

	vpn_leak_postchange(dir, afi, bgp_get_default(), bgp);
	return NB_OK;
}

static bool bgp_nb_vpn_rt_is_first(const struct lyd_node *dnode)
{
	const struct lyd_node *parent = lyd_parent(dnode);
	const struct lyd_node *child;

	LY_LIST_FOR (lyd_child(parent), child) {
		if (child->schema->nodetype != LYS_LEAFLIST)
			continue;
		if (!strmatch(child->schema->name, dnode->schema->name))
			continue;
		return child == dnode;
	}
	return true;
}

static struct ecommunity *bgp_nb_vpn_rt_ecom_from_parent(const struct lyd_node *parent,
							 const char *list_name)
{
	struct ecommunity *ecom = NULL, *add;
	const struct lyd_node *child;

	LY_LIST_FOR (lyd_child(parent), child) {
		if (child->schema->nodetype != LYS_LEAFLIST)
			continue;
		if (!strmatch(child->schema->name, list_name))
			continue;
		add = ecommunity_str2com(yang_dnode_get_string(child, NULL),
					 ECOMMUNITY_ROUTE_TARGET, 0);
		if (!add)
			continue;
		if (ecom) {
			ecommunity_merge(ecom, add);
			ecommunity_free(&add);
		} else
			ecom = add;
	}
	return ecom;
}

int bgp_nb_vpn_rt_import_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	struct ecommunity *ecom;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (bgp_nb_vpn_rt_parse(yang_dnode_get_string(args->dnode, NULL), &ecom,
					args->errmsg, args->errmsg_len) != NB_OK)
			return NB_ERR_VALIDATION;
		ecommunity_free(&ecom);
		bgp = nb_running_get_entry(args->dnode, NULL, false);
		if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
			return NB_OK;
		return bgp_nb_vpn_rmap_validate(bgp, afi, safi, args->errmsg, args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;
	if (bgp_nb_vpn_rt_parse(yang_dnode_get_string(args->dnode, NULL), &ecom, NULL, 0) != NB_OK)
		return NB_ERR_VALIDATION;

	return bgp_nb_vpn_rt_add(bgp, afi, BGP_VPN_POLICY_DIR_FROMVPN, ecom);
}

int bgp_nb_vpn_rt_import_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	struct ecommunity *ecom;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;
	if (bgp_nb_vpn_rt_parse(yang_dnode_get_string(args->dnode, NULL), &ecom, NULL, 0) != NB_OK)
		return NB_OK;

	bgp_nb_vpn_rt_del(bgp, afi, BGP_VPN_POLICY_DIR_FROMVPN, ecom);
	ecommunity_free(&ecom);
	return NB_OK;
}

void bgp_nb_cli_show_vpn_rt_import(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults)
{
	const struct lyd_node *parent;
	struct ecommunity *imp, *exp;
	char *b;

	if (!bgp_nb_vpn_rt_is_first(dnode))
		return;

	parent = lyd_parent(dnode);
	imp = bgp_nb_vpn_rt_ecom_from_parent(parent, "import-rt-list");
	exp = bgp_nb_vpn_rt_ecom_from_parent(parent, "export-rt-list");
	if (!imp) {
		if (exp)
			ecommunity_free(&exp);
		return;
	}

	b = ecommunity_ecom2str(imp, ECOMMUNITY_FORMAT_ROUTE_MAP, ECOMMUNITY_ROUTE_TARGET);
	if (exp && ecommunity_cmp(imp, exp))
		vty_out(vty, "  rt vpn both %s\n", b);
	else
		vty_out(vty, "  rt vpn import %s\n", b);
	XFREE(MTYPE_ECOMMUNITY_STR, b);
	ecommunity_free(&imp);
	if (exp)
		ecommunity_free(&exp);
}

int bgp_nb_vpn_rt_export_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	struct ecommunity *ecom;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (bgp_nb_vpn_rt_parse(yang_dnode_get_string(args->dnode, NULL), &ecom,
					args->errmsg, args->errmsg_len) != NB_OK)
			return NB_ERR_VALIDATION;
		ecommunity_free(&ecom);
		bgp = nb_running_get_entry(args->dnode, NULL, false);
		if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
			return NB_OK;
		return bgp_nb_vpn_rmap_validate(bgp, afi, safi, args->errmsg, args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;
	if (bgp_nb_vpn_rt_parse(yang_dnode_get_string(args->dnode, NULL), &ecom, NULL, 0) != NB_OK)
		return NB_ERR_VALIDATION;

	return bgp_nb_vpn_rt_add(bgp, afi, BGP_VPN_POLICY_DIR_TOVPN, ecom);
}

int bgp_nb_vpn_rt_export_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	struct ecommunity *ecom;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;
	if (bgp_nb_vpn_rt_parse(yang_dnode_get_string(args->dnode, NULL), &ecom, NULL, 0) != NB_OK)
		return NB_OK;

	bgp_nb_vpn_rt_del(bgp, afi, BGP_VPN_POLICY_DIR_TOVPN, ecom);
	ecommunity_free(&ecom);
	return NB_OK;
}

void bgp_nb_cli_show_vpn_rt_export(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults)
{
	const struct lyd_node *parent;
	struct ecommunity *imp, *exp;
	char *b;

	if (!bgp_nb_vpn_rt_is_first(dnode))
		return;

	parent = lyd_parent(dnode);
	imp = bgp_nb_vpn_rt_ecom_from_parent(parent, "import-rt-list");
	exp = bgp_nb_vpn_rt_ecom_from_parent(parent, "export-rt-list");
	if (!exp) {
		if (imp)
			ecommunity_free(&imp);
		return;
	}

	if (imp && ecommunity_cmp(imp, exp)) {
		ecommunity_free(&imp);
		ecommunity_free(&exp);
		return;
	}

	b = ecommunity_ecom2str(exp, ECOMMUNITY_FORMAT_ROUTE_MAP, ECOMMUNITY_ROUTE_TARGET);
	vty_out(vty, "  rt vpn export %s\n", b);
	XFREE(MTYPE_ECOMMUNITY_STR, b);
	if (imp)
		ecommunity_free(&imp);
	ecommunity_free(&exp);
}

/*
 * AF-level import vrf NAME
 */
static int bgp_nb_vpn_import_vrf_mode_validate(struct bgp *bgp, afi_t afi, safi_t safi,
					       char *errmsg, size_t errmsg_len)
{
	if (safi != SAFI_UNICAST || (afi != AFI_IP && afi != AFI_IP6)) {
		snprintfrr(errmsg, errmsg_len, "import vrf valid only for unicast ipv4|ipv6");
		return NB_ERR_VALIDATION;
	}

	if (CHECK_FLAG(bgp->af_flags[afi][safi], BGP_CONFIG_VRF_TO_MPLSVPN_EXPORT) ||
	    CHECK_FLAG(bgp->af_flags[afi][safi], BGP_CONFIG_MPLSVPN_TO_VRF_IMPORT)) {
		snprintfrr(errmsg, errmsg_len,
			   "Please unconfigure vpn to vrf commands before using import vrf commands");
		return NB_ERR_VALIDATION;
	}

	return NB_OK;
}

static int bgp_nb_vpn_import_vrf_validate(struct bgp *bgp, afi_t afi, safi_t safi,
					  const char *import_name, char *errmsg, size_t errmsg_len)
{
	int ret;

	ret = bgp_nb_vpn_import_vrf_mode_validate(bgp, afi, safi, errmsg, errmsg_len);
	if (ret != NB_OK)
		return ret;

	if (((bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT) &&
	     strmatch(import_name, VRF_DEFAULT_NAME)) ||
	    (bgp->name && strmatch(import_name, bgp->name))) {
		snprintfrr(errmsg, errmsg_len, "Cannot import vrf %s into itself", import_name);
		return NB_ERR_VALIDATION;
	}

	return NB_OK;
}

static struct bgp *bgp_nb_vpn_ensure_default(void)
{
	struct bgp *bgp_default = bgp_get_default();
	as_t as = BGP_AS_ZERO;
	int ret;

	if (bgp_default)
		return bgp_default;

	ret = bgp_get_vty(&bgp_default, &as, NULL, BGP_INSTANCE_TYPE_DEFAULT, NULL,
			  ASNOTATION_UNDEFINED);
	if (ret)
		return NULL;

	SET_FLAG(bgp_default->flags, BGP_FLAG_INSTANCE_HIDDEN);
	return bgp_default;
}

int bgp_nb_vpn_import_vrf_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp, *vrf_bgp, *bgp_default;
	afi_t afi;
	safi_t safi;
	const char *import_name;

	import_name = yang_dnode_get_string(args->dnode, "./vrf");

	switch (args->event) {
	case NB_EV_VALIDATE:
		bgp = nb_running_get_entry(args->dnode, NULL, false);
		if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
			return NB_OK;
		return bgp_nb_vpn_import_vrf_validate(bgp, afi, safi, import_name, args->errmsg,
						      args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	bgp_default = bgp_nb_vpn_ensure_default();
	if (!bgp_default)
		return NB_ERR_RESOURCE;

	if (strmatch(import_name, VRF_DEFAULT_NAME))
		vrf_bgp = bgp_default;
	else
		vrf_bgp = bgp_lookup_by_name_filter(import_name, false);

	vrf_import_from_vrf(bgp, vrf_bgp, import_name, afi, safi);
	return NB_OK;
}

int bgp_nb_vpn_import_vrf_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp, *vrf_bgp, *bgp_default;
	afi_t afi;
	safi_t safi;
	const char *import_name;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	import_name = yang_dnode_get_string(args->dnode, "./vrf");
	bgp_default = bgp_get_default();
	if (strmatch(import_name, VRF_DEFAULT_NAME))
		vrf_bgp = bgp_default;
	else
		vrf_bgp = bgp_lookup_by_name_filter(import_name, false);

	vrf_unimport_from_vrf(bgp, vrf_bgp, import_name, afi, safi);
	return NB_OK;
}

void bgp_nb_cli_show_vpn_import_vrf(struct vty *vty, const struct lyd_node *dnode,
				    bool show_defaults)
{
	vty_out(vty, "  import vrf %s\n", yang_dnode_get_string(dnode, "./vrf"));
}

/*
 * AF-level import vrf route-map
 */
int bgp_nb_vpn_vrf_rmap_import_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	const char *rmap_name;

	rmap_name = yang_dnode_get_string(args->dnode, NULL);

	switch (args->event) {
	case NB_EV_VALIDATE:
		bgp = nb_running_get_entry(args->dnode, NULL, false);
		if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
			return NB_OK;
		if (yang_dnode_exists(args->dnode, "../rmap-import")) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "import vrf route-map conflicts with route-map vpn import");
			return NB_ERR_VALIDATION;
		}
		return bgp_nb_vpn_import_vrf_mode_validate(bgp, afi, safi, args->errmsg,
							   args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	if (!bgp_nb_vpn_ensure_default())
		return NB_ERR_RESOURCE;

	vpn_leak_prechange(BGP_VPN_POLICY_DIR_FROMVPN, afi, bgp_get_default(), bgp);

	if (bgp->vpn_policy[afi].rmap_name[BGP_VPN_POLICY_DIR_FROMVPN])
		XFREE(MTYPE_ROUTE_MAP_NAME,
		      bgp->vpn_policy[afi].rmap_name[BGP_VPN_POLICY_DIR_FROMVPN]);
	bgp->vpn_policy[afi].rmap_name[BGP_VPN_POLICY_DIR_FROMVPN] = XSTRDUP(MTYPE_ROUTE_MAP_NAME,
									     rmap_name);
	bgp->vpn_policy[afi].rmap[BGP_VPN_POLICY_DIR_FROMVPN] = route_map_lookup_by_name(rmap_name);

	SET_FLAG(bgp->af_flags[afi][SAFI_UNICAST], BGP_CONFIG_VRF_TO_VRF_IMPORT);

	if (bgp->vpn_policy[afi].rmap[BGP_VPN_POLICY_DIR_FROMVPN])
		vpn_leak_postchange(BGP_VPN_POLICY_DIR_FROMVPN, afi, bgp_get_default(), bgp);
	return NB_OK;
}

int bgp_nb_vpn_vrf_rmap_import_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	vpn_leak_prechange(BGP_VPN_POLICY_DIR_FROMVPN, afi, bgp_get_default(), bgp);

	if (bgp->vpn_policy[afi].rmap_name[BGP_VPN_POLICY_DIR_FROMVPN])
		XFREE(MTYPE_ROUTE_MAP_NAME,
		      bgp->vpn_policy[afi].rmap_name[BGP_VPN_POLICY_DIR_FROMVPN]);
	bgp->vpn_policy[afi].rmap_name[BGP_VPN_POLICY_DIR_FROMVPN] = NULL;
	bgp->vpn_policy[afi].rmap[BGP_VPN_POLICY_DIR_FROMVPN] = NULL;

	if (!bgp->vpn_policy[afi].import_vrf || bgp->vpn_policy[afi].import_vrf->count == 0)
		UNSET_FLAG(bgp->af_flags[afi][SAFI_UNICAST], BGP_CONFIG_VRF_TO_VRF_IMPORT);

	vpn_leak_postchange(BGP_VPN_POLICY_DIR_FROMVPN, afi, bgp_get_default(), bgp);
	return NB_OK;
}

void bgp_nb_cli_show_vpn_vrf_rmap_import(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults)
{
	vty_out(vty, "  import vrf route-map %s\n", yang_dnode_get_string(dnode, NULL));
}

/*
 * L3VPN bgp retain route-target all
 */
int bgp_nb_vpn_retain_rt_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	bool retain;
	bool previous;

	retain = yang_dnode_get_bool(args->dnode, NULL);

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	previous = !!CHECK_FLAG(bgp->af_flags[afi][safi], BGP_VPNVX_RETAIN_ROUTE_TARGET_ALL);
	if (previous == retain)
		return NB_OK;

	if (retain)
		SET_FLAG(bgp->af_flags[afi][safi], BGP_VPNVX_RETAIN_ROUTE_TARGET_ALL);
	else
		UNSET_FLAG(bgp->af_flags[afi][safi], BGP_VPNVX_RETAIN_ROUTE_TARGET_ALL);

	bgp_clear_soft_in(bgp, afi, safi);
	return NB_OK;
}

int bgp_nb_vpn_retain_rt_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	/* Default is retain-all (true). */
	if (CHECK_FLAG(bgp->af_flags[afi][safi], BGP_VPNVX_RETAIN_ROUTE_TARGET_ALL))
		return NB_OK;

	SET_FLAG(bgp->af_flags[afi][safi], BGP_VPNVX_RETAIN_ROUTE_TARGET_ALL);
	bgp_clear_soft_in(bgp, afi, safi);
	return NB_OK;
}

void bgp_nb_cli_show_vpn_retain_rt(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "  no bgp retain route-target all\n");
	else if (show_defaults)
		vty_out(vty, "  bgp retain route-target all\n");
}

/*
 * AF-level rt[6] redirect import
 */
static int bgp_nb_vpn_redirect_rt_parse(const char *rt_str, bool ipv6, struct ecommunity **ecom,
					char *errmsg, size_t errmsg_len)
{
	char *copy, *token, *save;
	struct ecommunity *add;

	*ecom = NULL;
	copy = XSTRDUP(MTYPE_TMP, rt_str);
	for (token = strtok_r(copy, " \t", &save); token; token = strtok_r(NULL, " \t", &save)) {
		if (ipv6)
			add = ecommunity_str2com_ipv6(token, ECOMMUNITY_ROUTE_TARGET, 0);
		else
			add = ecommunity_str2com(token, ECOMMUNITY_ROUTE_TARGET, 0);
		if (!add) {
			if (errmsg)
				snprintfrr(errmsg, errmsg_len, "Malformed community-list value");
			if (*ecom)
				ecommunity_free(ecom);
			XFREE(MTYPE_TMP, copy);
			return NB_ERR_VALIDATION;
		}
		if (*ecom) {
			ecommunity_merge(*ecom, add);
			ecommunity_free(&add);
		} else
			*ecom = add;
	}
	XFREE(MTYPE_TMP, copy);
	if (!*ecom) {
		if (errmsg)
			snprintfrr(errmsg, errmsg_len, "Missing RTLIST");
		return NB_ERR_VALIDATION;
	}
	return NB_OK;
}

static int bgp_nb_vpn_redirect_rt_apply(struct bgp *bgp, afi_t afi, struct ecommunity *ecom)
{
	if (bgp->vpn_policy[afi].import_redirect_rtlist)
		ecommunity_free(&bgp->vpn_policy[afi].import_redirect_rtlist);
	bgp->vpn_policy[afi].import_redirect_rtlist = ecom;
	return NB_OK;
}

int bgp_nb_vpn_redirect_rt_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	struct ecommunity *ecom;
	bool ipv6 = false;

	if (yang_dnode_exists(args->dnode, "../redirect-rt-ipv6"))
		ipv6 = yang_dnode_get_bool(args->dnode, "../redirect-rt-ipv6");

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (bgp_nb_vpn_redirect_rt_parse(yang_dnode_get_string(args->dnode, NULL), ipv6,
						 &ecom, args->errmsg, args->errmsg_len) != NB_OK)
			return NB_ERR_VALIDATION;
		ecommunity_free(&ecom);
		bgp = nb_running_get_entry(args->dnode, NULL, false);
		if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
			return NB_OK;
		if (ipv6 && afi != AFI_IP6) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "rt6 redirect import valid only for ipv6");
			return NB_ERR_VALIDATION;
		}
		return bgp_nb_vpn_rmap_validate(bgp, afi, safi, args->errmsg, args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;
	if (bgp_nb_vpn_redirect_rt_parse(yang_dnode_get_string(args->dnode, NULL), ipv6, &ecom,
					 NULL, 0) != NB_OK)
		return NB_ERR_VALIDATION;

	return bgp_nb_vpn_redirect_rt_apply(bgp, afi, ecom);
}

int bgp_nb_vpn_redirect_rt_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	return bgp_nb_vpn_redirect_rt_apply(bgp, afi, NULL);
}

void bgp_nb_cli_show_vpn_redirect_rt(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults)
{
	bool ipv6 = false;

	if (yang_dnode_exists(dnode, "../redirect-rt-ipv6"))
		ipv6 = yang_dnode_get_bool(dnode, "../redirect-rt-ipv6");

	vty_out(vty, "  %s redirect import %s\n", ipv6 ? "rt6" : "rt",
		yang_dnode_get_string(dnode, NULL));
}

static int bgp_nb_vpn_redirect_rt_ipv6_sync(const struct lyd_node *dnode, bool ipv6,
					   enum nb_event event, char *errmsg, size_t errmsg_len)
{
	const struct lyd_node *parent;
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	struct ecommunity *ecom = NULL;
	int ret;

	if (event != NB_EV_VALIDATE && event != NB_EV_APPLY)
		return NB_OK;

	parent = yang_dnode_get_parent(dnode, "vpn-config");
	if (!parent || !yang_dnode_exists(parent, "redirect-rt"))
		return NB_OK;

	ret = bgp_nb_vpn_redirect_rt_parse(yang_dnode_get_string(parent, "redirect-rt"), ipv6, &ecom,
					   errmsg, errmsg_len);
	if (ret != NB_OK)
		return ret;

	bgp = nb_running_get_entry(dnode, NULL, event == NB_EV_APPLY);
	if (!bgp || !bgp_nb_dnode_afi_safi(dnode, &afi, &safi)) {
		ecommunity_free(&ecom);
		return NB_OK;
	}
	if (ipv6 && afi != AFI_IP6) {
		ecommunity_free(&ecom);
		snprintfrr(errmsg, errmsg_len, "rt6 redirect import valid only for ipv6");
		return NB_ERR_VALIDATION;
	}
	if (event != NB_EV_APPLY) {
		ecommunity_free(&ecom);
		return NB_OK;
	}
	return bgp_nb_vpn_redirect_rt_apply(bgp, afi, ecom);
}

int bgp_nb_vpn_redirect_rt_ipv6_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_vpn_redirect_rt_ipv6_sync(args->dnode, yang_dnode_get_bool(args->dnode, NULL),
					       args->event, args->errmsg, args->errmsg_len);
}

int bgp_nb_vpn_redirect_rt_ipv6_destroy(struct nb_cb_destroy_args *args)
{
	/* Destroying the flag means the sibling RT is interpreted as IPv4. */
	return bgp_nb_vpn_redirect_rt_ipv6_sync(args->dnode, false, args->event, args->errmsg,
					       args->errmsg_len);
}

/*
 * AF-level sid vpn export (per-AFI SRv6 VPN SID)
 */
enum bgp_nb_sid_vpn_mode {
	BGP_NB_SID_VPN_NONE = 0,
	BGP_NB_SID_VPN_AUTO,
	BGP_NB_SID_VPN_INDEX,
	BGP_NB_SID_VPN_EXPLICIT,
};

static void bgp_nb_sid_vpn_export_clear(struct bgp *bgp, afi_t afi)
{
	if (!is_srv6_vpn_afi_enabled(bgp, afi))
		return;

	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);
	bgp->vpn_policy[afi].tovpn_sid_index = 0;
	UNSET_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_SID_AUTO);
	UNSET_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_SID_EXPLICIT);
	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);
}

static void bgp_nb_sid_vpn_export_read(const struct lyd_node *cont, enum bgp_nb_sid_vpn_mode *mode,
				       uint32_t *idx, struct in6_addr *explicit)
{
	*mode = BGP_NB_SID_VPN_NONE;
	*idx = 0;
	memset(explicit, 0, sizeof(*explicit));

	if (!cont)
		return;

	if (yang_dnode_exists(cont, "./sid-auto"))
		*mode = BGP_NB_SID_VPN_AUTO;
	else if (yang_dnode_exists(cont, "./sid-index")) {
		*mode = BGP_NB_SID_VPN_INDEX;
		*idx = yang_dnode_get_uint32(cont, "./sid-index");
	} else if (yang_dnode_exists(cont, "./sid-explicit")) {
		*mode = BGP_NB_SID_VPN_EXPLICIT;
		inet_pton(AF_INET6, yang_dnode_get_string(cont, "./sid-explicit"), explicit);
	}
}

static int bgp_nb_sid_vpn_export_validate(struct bgp *bgp, afi_t afi, enum bgp_nb_sid_vpn_mode mode,
					  char *errmsg, size_t errmsg_len)
{
	if (mode == BGP_NB_SID_VPN_NONE)
		return NB_OK;

	if (is_srv6_vpn_vrf_enabled(bgp)) {
		snprintfrr(errmsg, errmsg_len,
			   "sid vpn per-vrf sid and per-af sid are mutually exclusive");
		return NB_ERR_VALIDATION;
	}
	if (is_srv6_unicast_enabled(bgp, afi)) {
		snprintfrr(errmsg, errmsg_len,
			   "sid export is configured on unicast; remove it before sid vpn");
		return NB_ERR_VALIDATION;
	}

	if (!is_srv6_vpn_afi_enabled(bgp, afi))
		return NB_OK;

	{
		bool cur_auto = CHECK_FLAG(bgp->vpn_policy[afi].flags,
					   BGP_VPN_POLICY_TOVPN_SID_AUTO);
		bool cur_explicit = CHECK_FLAG(bgp->vpn_policy[afi].flags,
					       BGP_VPN_POLICY_TOVPN_SID_EXPLICIT);
		uint32_t cur_idx = bgp->vpn_policy[afi].tovpn_sid_index;
		bool same_family = (mode == BGP_NB_SID_VPN_AUTO && cur_auto) ||
				   (mode == BGP_NB_SID_VPN_INDEX && cur_idx != 0) ||
				   (mode == BGP_NB_SID_VPN_EXPLICIT && cur_explicit);

		if (same_family)
			return NB_OK;

		if (cur_idx != 0 && mode != BGP_NB_SID_VPN_INDEX) {
			snprintfrr(errmsg, errmsg_len, "it's already configured as idx-mode");
			return NB_ERR_VALIDATION;
		}
		if (cur_explicit && mode != BGP_NB_SID_VPN_EXPLICIT) {
			snprintfrr(errmsg, errmsg_len, "it's already configured as explicit-mode");
			return NB_ERR_VALIDATION;
		}
		if (cur_auto && mode != BGP_NB_SID_VPN_AUTO) {
			snprintfrr(errmsg, errmsg_len, "it's already configured as auto-mode");
			return NB_ERR_VALIDATION;
		}
	}
	return NB_OK;
}

static int bgp_nb_sid_vpn_export_apply(struct bgp *bgp, afi_t afi, const struct lyd_node *cont)
{
	enum bgp_nb_sid_vpn_mode mode;
	uint32_t idx;
	struct in6_addr explicit;
	bool same_family;

	bgp_nb_sid_vpn_export_read(cont, &mode, &idx, &explicit);

	if (mode == BGP_NB_SID_VPN_NONE) {
		bgp_nb_sid_vpn_export_clear(bgp, afi);
		return NB_OK;
	}

	same_family = (mode == BGP_NB_SID_VPN_AUTO &&
		       CHECK_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_SID_AUTO)) ||
		      (mode == BGP_NB_SID_VPN_INDEX && bgp->vpn_policy[afi].tovpn_sid_index != 0) ||
		      (mode == BGP_NB_SID_VPN_EXPLICIT &&
		       CHECK_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_SID_EXPLICIT));
	if (same_family)
		return NB_OK;

	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);

	if (mode == BGP_NB_SID_VPN_AUTO) {
		SET_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_SID_AUTO);
	} else if (mode == BGP_NB_SID_VPN_INDEX) {
		bgp->vpn_policy[afi].tovpn_sid_index = idx;
	} else if (mode == BGP_NB_SID_VPN_EXPLICIT) {
		if (!bgp->vpn_policy[afi].tovpn_sid_explicit)
			bgp->vpn_policy[afi].tovpn_sid_explicit = XCALLOC(MTYPE_BGP_SRV6_SID,
									  sizeof(struct in6_addr));
		IPV6_ADDR_COPY(bgp->vpn_policy[afi].tovpn_sid_explicit, &explicit);
		SET_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_SID_EXPLICIT);
	}

	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);
	return NB_OK;
}

static int bgp_nb_sid_vpn_export_from_dnode(const struct lyd_node *dnode, enum nb_event event,
					    char *errmsg, size_t errmsg_len)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	const struct lyd_node *cont;
	enum bgp_nb_sid_vpn_mode mode;
	uint32_t idx;
	struct in6_addr explicit;

	cont = yang_dnode_get_parent(dnode, "sid-vpn-export");
	bgp_nb_sid_vpn_export_read(cont, &mode, &idx, &explicit);

	switch (event) {
	case NB_EV_VALIDATE:
		bgp = nb_running_get_entry(dnode, NULL, false);
		if (!bgp || !bgp_nb_dnode_afi_safi(dnode, &afi, &safi))
			return NB_OK;
		return bgp_nb_sid_vpn_export_validate(bgp, afi, mode, errmsg, errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_get_entry(dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	return bgp_nb_sid_vpn_export_apply(bgp, afi, cont);
}

int bgp_nb_sid_vpn_export_index_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_sid_vpn_export_from_dnode(args->dnode, args->event, args->errmsg,
						args->errmsg_len);
}

int bgp_nb_sid_vpn_export_index_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	const struct lyd_node *cont;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	cont = yang_dnode_get_parent(args->dnode, "sid-vpn-export");
	if (cont &&
	    (yang_dnode_exists(cont, "./sid-auto") || yang_dnode_exists(cont, "./sid-explicit")))
		return NB_OK;

	bgp_nb_sid_vpn_export_clear(bgp, afi);
	return NB_OK;
}

int bgp_nb_sid_vpn_export_auto_create(struct nb_cb_create_args *args)
{
	return bgp_nb_sid_vpn_export_from_dnode(args->dnode, args->event, args->errmsg,
						args->errmsg_len);
}

int bgp_nb_sid_vpn_export_auto_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	const struct lyd_node *cont;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	cont = yang_dnode_get_parent(args->dnode, "sid-vpn-export");
	if (cont &&
	    (yang_dnode_exists(cont, "./sid-index") || yang_dnode_exists(cont, "./sid-explicit")))
		return NB_OK;

	bgp_nb_sid_vpn_export_clear(bgp, afi);
	return NB_OK;
}

int bgp_nb_sid_vpn_export_explicit_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_sid_vpn_export_from_dnode(args->dnode, args->event, args->errmsg,
						args->errmsg_len);
}

int bgp_nb_sid_vpn_export_explicit_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	const struct lyd_node *cont;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	cont = yang_dnode_get_parent(args->dnode, "sid-vpn-export");
	if (cont &&
	    (yang_dnode_exists(cont, "./sid-index") || yang_dnode_exists(cont, "./sid-auto")))
		return NB_OK;

	bgp_nb_sid_vpn_export_clear(bgp, afi);
	return NB_OK;
}

void bgp_nb_cli_show_sid_vpn_export(struct vty *vty, const struct lyd_node *dnode,
				    bool show_defaults)
{
	const struct lyd_node *cont = yang_dnode_get_parent(dnode, "sid-vpn-export");
	enum bgp_nb_sid_vpn_mode mode;
	uint32_t idx;
	struct in6_addr explicit;
	char buf[INET6_ADDRSTRLEN];

	bgp_nb_sid_vpn_export_read(cont, &mode, &idx, &explicit);
	if (mode == BGP_NB_SID_VPN_NONE)
		return;

	if (mode == BGP_NB_SID_VPN_AUTO && !strmatch(dnode->schema->name, "sid-auto"))
		return;
	if (mode == BGP_NB_SID_VPN_INDEX && !strmatch(dnode->schema->name, "sid-index"))
		return;
	if (mode == BGP_NB_SID_VPN_EXPLICIT && !strmatch(dnode->schema->name, "sid-explicit"))
		return;

	if (mode == BGP_NB_SID_VPN_AUTO)
		vty_out(vty, "  sid vpn export auto\n");
	else if (mode == BGP_NB_SID_VPN_EXPLICIT) {
		inet_ntop(AF_INET6, &explicit, buf, sizeof(buf));
		vty_out(vty, "  sid vpn export explicit %s\n", buf);
	} else
		vty_out(vty, "  sid vpn export %u\n", idx);
}

/*
 * Global sid vpn per-vrf export
 */
static void bgp_nb_sid_vpn_per_vrf_clear(struct bgp *bgp)
{
	if (!is_srv6_vpn_vrf_enabled(bgp))
		return;

	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, AFI_IP, bgp_get_default(), bgp);
	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, AFI_IP6, bgp_get_default(), bgp);
	bgp->tovpn_sid_index = 0;
	UNSET_FLAG(bgp->vrf_flags, BGP_VRF_TOVPN_SID_AUTO);
	UNSET_FLAG(bgp->vrf_flags, BGP_VRF_TOVPN_SID_EXPLICIT);
	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, AFI_IP, bgp_get_default(), bgp);
	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, AFI_IP6, bgp_get_default(), bgp);
}

static void bgp_nb_sid_vpn_per_vrf_read(const struct lyd_node *cont, enum bgp_nb_sid_vpn_mode *mode,
					uint32_t *idx, struct in6_addr *explicit)
{
	bgp_nb_sid_vpn_export_read(cont, mode, idx, explicit);
}

static int bgp_nb_sid_vpn_per_vrf_validate(struct bgp *bgp, enum bgp_nb_sid_vpn_mode mode,
					   char *errmsg, size_t errmsg_len)
{
	if (mode == BGP_NB_SID_VPN_NONE)
		return NB_OK;

	if (is_srv6_vpn_afi_enabled(bgp, AFI_IP) || is_srv6_vpn_afi_enabled(bgp, AFI_IP6)) {
		snprintfrr(errmsg, errmsg_len, "per-vrf sid and per-af sid are mutually exclusive");
		return NB_ERR_VALIDATION;
	}
	if (is_srv6_unicast_enabled(bgp, AFI_IP) || is_srv6_unicast_enabled(bgp, AFI_IP6)) {
		snprintfrr(errmsg, errmsg_len,
			   "sid export is configured on unicast; remove it before sid vpn");
		return NB_ERR_VALIDATION;
	}

	if (!is_srv6_vpn_vrf_enabled(bgp))
		return NB_OK;

	{
		bool cur_auto = CHECK_FLAG(bgp->vrf_flags, BGP_VRF_TOVPN_SID_AUTO);
		bool cur_explicit = CHECK_FLAG(bgp->vrf_flags, BGP_VRF_TOVPN_SID_EXPLICIT);
		uint32_t cur_idx = bgp->tovpn_sid_index;
		bool same_family = (mode == BGP_NB_SID_VPN_AUTO && cur_auto) ||
				   (mode == BGP_NB_SID_VPN_INDEX && cur_idx != 0) ||
				   (mode == BGP_NB_SID_VPN_EXPLICIT && cur_explicit);

		if (same_family)
			return NB_OK;

		if (cur_idx != 0 && mode != BGP_NB_SID_VPN_INDEX) {
			snprintfrr(errmsg, errmsg_len, "it's already configured as idx-mode");
			return NB_ERR_VALIDATION;
		}
		if (cur_explicit && mode != BGP_NB_SID_VPN_EXPLICIT) {
			snprintfrr(errmsg, errmsg_len, "it's already configured as explicit-mode");
			return NB_ERR_VALIDATION;
		}
		if (cur_auto && mode != BGP_NB_SID_VPN_AUTO) {
			snprintfrr(errmsg, errmsg_len, "it's already configured as auto-mode");
			return NB_ERR_VALIDATION;
		}
	}
	return NB_OK;
}

static int bgp_nb_sid_vpn_per_vrf_apply(struct bgp *bgp, const struct lyd_node *cont)
{
	enum bgp_nb_sid_vpn_mode mode;
	uint32_t idx;
	struct in6_addr explicit;
	bool same_family;

	bgp_nb_sid_vpn_per_vrf_read(cont, &mode, &idx, &explicit);

	if (mode == BGP_NB_SID_VPN_NONE) {
		bgp_nb_sid_vpn_per_vrf_clear(bgp);
		return NB_OK;
	}

	same_family = (mode == BGP_NB_SID_VPN_AUTO &&
		       CHECK_FLAG(bgp->vrf_flags, BGP_VRF_TOVPN_SID_AUTO)) ||
		      (mode == BGP_NB_SID_VPN_INDEX && bgp->tovpn_sid_index != 0) ||
		      (mode == BGP_NB_SID_VPN_EXPLICIT &&
		       CHECK_FLAG(bgp->vrf_flags, BGP_VRF_TOVPN_SID_EXPLICIT));
	if (same_family)
		return NB_OK;

	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, AFI_IP, bgp_get_default(), bgp);
	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, AFI_IP6, bgp_get_default(), bgp);

	if (mode == BGP_NB_SID_VPN_AUTO) {
		SET_FLAG(bgp->vrf_flags, BGP_VRF_TOVPN_SID_AUTO);
	} else if (mode == BGP_NB_SID_VPN_INDEX) {
		bgp->tovpn_sid_index = idx;
	} else if (mode == BGP_NB_SID_VPN_EXPLICIT) {
		if (!bgp->tovpn_sid_explicit)
			bgp->tovpn_sid_explicit = XCALLOC(MTYPE_BGP_SRV6_SID,
							  sizeof(struct in6_addr));
		IPV6_ADDR_COPY(bgp->tovpn_sid_explicit, &explicit);
		SET_FLAG(bgp->vrf_flags, BGP_VRF_TOVPN_SID_EXPLICIT);
	}

	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, AFI_IP, bgp_get_default(), bgp);
	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, AFI_IP6, bgp_get_default(), bgp);
	return NB_OK;
}

static int bgp_nb_sid_vpn_per_vrf_from_dnode(const struct lyd_node *dnode, enum nb_event event,
					     char *errmsg, size_t errmsg_len)
{
	struct bgp *bgp;
	const struct lyd_node *cont;
	enum bgp_nb_sid_vpn_mode mode;
	uint32_t idx;
	struct in6_addr explicit;

	cont = yang_dnode_get_parent(dnode, "sid-vpn-per-vrf-export");
	bgp_nb_sid_vpn_per_vrf_read(cont, &mode, &idx, &explicit);

	switch (event) {
	case NB_EV_VALIDATE:
		bgp = nb_running_get_entry(dnode, NULL, false);
		if (!bgp)
			return NB_OK;
		return bgp_nb_sid_vpn_per_vrf_validate(bgp, mode, errmsg, errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_get_entry(dnode, NULL, true);
	if (!bgp)
		return NB_ERR_NOT_FOUND;

	return bgp_nb_sid_vpn_per_vrf_apply(bgp, cont);
}

int bgp_nb_sid_vpn_per_vrf_index_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_sid_vpn_per_vrf_from_dnode(args->dnode, args->event, args->errmsg,
						 args->errmsg_len);
}

int bgp_nb_sid_vpn_per_vrf_index_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const struct lyd_node *cont;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp)
		return NB_OK;

	cont = yang_dnode_get_parent(args->dnode, "sid-vpn-per-vrf-export");
	if (cont &&
	    (yang_dnode_exists(cont, "./sid-auto") || yang_dnode_exists(cont, "./sid-explicit")))
		return NB_OK;

	bgp_nb_sid_vpn_per_vrf_clear(bgp);
	return NB_OK;
}

int bgp_nb_sid_vpn_per_vrf_auto_create(struct nb_cb_create_args *args)
{
	return bgp_nb_sid_vpn_per_vrf_from_dnode(args->dnode, args->event, args->errmsg,
						 args->errmsg_len);
}

int bgp_nb_sid_vpn_per_vrf_auto_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const struct lyd_node *cont;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp)
		return NB_OK;

	cont = yang_dnode_get_parent(args->dnode, "sid-vpn-per-vrf-export");
	if (cont &&
	    (yang_dnode_exists(cont, "./sid-index") || yang_dnode_exists(cont, "./sid-explicit")))
		return NB_OK;

	bgp_nb_sid_vpn_per_vrf_clear(bgp);
	return NB_OK;
}

int bgp_nb_sid_vpn_per_vrf_explicit_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_sid_vpn_per_vrf_from_dnode(args->dnode, args->event, args->errmsg,
						 args->errmsg_len);
}

int bgp_nb_sid_vpn_per_vrf_explicit_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const struct lyd_node *cont;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp)
		return NB_OK;

	cont = yang_dnode_get_parent(args->dnode, "sid-vpn-per-vrf-export");
	if (cont &&
	    (yang_dnode_exists(cont, "./sid-index") || yang_dnode_exists(cont, "./sid-auto")))
		return NB_OK;

	bgp_nb_sid_vpn_per_vrf_clear(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_sid_vpn_per_vrf(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults)
{
	const struct lyd_node *cont = yang_dnode_get_parent(dnode, "sid-vpn-per-vrf-export");
	enum bgp_nb_sid_vpn_mode mode;
	uint32_t idx;
	struct in6_addr explicit;
	char buf[INET6_ADDRSTRLEN];

	bgp_nb_sid_vpn_per_vrf_read(cont, &mode, &idx, &explicit);
	if (mode == BGP_NB_SID_VPN_NONE)
		return;

	if (mode == BGP_NB_SID_VPN_AUTO && !strmatch(dnode->schema->name, "sid-auto"))
		return;
	if (mode == BGP_NB_SID_VPN_INDEX && !strmatch(dnode->schema->name, "sid-index"))
		return;
	if (mode == BGP_NB_SID_VPN_EXPLICIT && !strmatch(dnode->schema->name, "sid-explicit"))
		return;

	if (mode == BGP_NB_SID_VPN_AUTO)
		vty_out(vty, " sid vpn per-vrf export auto\n");
	else if (mode == BGP_NB_SID_VPN_EXPLICIT) {
		inet_ntop(AF_INET6, &explicit, buf, sizeof(buf));
		vty_out(vty, " sid vpn per-vrf export explicit %s\n", buf);
	} else
		vty_out(vty, " sid vpn per-vrf export %u\n", idx);
}

/*
 * AF-level sid export (SRv6 unicast)
 */
enum bgp_nb_sid_export_mode {
	BGP_NB_SID_NONE = 0,
	BGP_NB_SID_AUTO,
	BGP_NB_SID_INDEX,
	BGP_NB_SID_EXPLICIT,
};

static void bgp_nb_sid_export_clear(struct bgp *bgp, afi_t afi)
{
	if (!is_srv6_unicast_enabled(bgp, afi))
		return;

	if (bgp->srv6_unicast[afi].rmap_name) {
		route_map_counter_decrement(
			route_map_lookup_by_name(bgp->srv6_unicast[afi].rmap_name));
		XFREE(MTYPE_ROUTE_MAP_NAME, bgp->srv6_unicast[afi].rmap_name);
		bgp->srv6_unicast[afi].rmap_name = NULL;
	}
	if (bgp->srv6_unicast[afi].sid_explicit) {
		XFREE(MTYPE_BGP_SRV6_SID, bgp->srv6_unicast[afi].sid_explicit);
		bgp->srv6_unicast[afi].sid_explicit = NULL;
	}
	bgp->srv6_unicast[afi].sid_index = 0;
	UNSET_FLAG(bgp->srv6_unicast[afi].flags, SRV6_POLICY_FLAG_SID_AUTO);
	bgp_srv6_unicast_sid_withdraw(bgp, afi);
	UNSET_FLAG(bgp->srv6_unicast[afi].flags, SRV6_POLICY_FLAG_BEHAVIOR_DT46);
}

static void bgp_nb_sid_export_read(const struct lyd_node *cont, enum bgp_nb_sid_export_mode *mode,
				   uint32_t *idx, struct in6_addr *explicit, bool *dt46,
				   const char **rmap)
{
	*mode = BGP_NB_SID_NONE;
	*idx = 0;
	*dt46 = false;
	*rmap = NULL;
	memset(explicit, 0, sizeof(*explicit));

	if (!cont)
		return;

	if (yang_dnode_exists(cont, "./sid-auto"))
		*mode = BGP_NB_SID_AUTO;
	else if (yang_dnode_exists(cont, "./sid-index")) {
		*mode = BGP_NB_SID_INDEX;
		*idx = yang_dnode_get_uint32(cont, "./sid-index");
	} else if (yang_dnode_exists(cont, "./sid-explicit")) {
		*mode = BGP_NB_SID_EXPLICIT;
		inet_pton(AF_INET6, yang_dnode_get_string(cont, "./sid-explicit"), explicit);
	}

	if (yang_dnode_exists(cont, "./behavior-dt46"))
		*dt46 = yang_dnode_get_bool(cont, "./behavior-dt46");
	if (yang_dnode_exists(cont, "./route-map"))
		*rmap = yang_dnode_get_string(cont, "./route-map");
}

static int bgp_nb_sid_export_validate(struct bgp *bgp, afi_t afi, enum bgp_nb_sid_export_mode mode,
				      uint32_t idx, const struct in6_addr *explicit, bool dt46,
				      char *errmsg, size_t errmsg_len)
{
	afi_t other_afi;

	if (bgp->inst_type != BGP_INSTANCE_TYPE_DEFAULT) {
		snprintfrr(errmsg, errmsg_len,
			   "SRv6 unicast is only supported on the default BGP instance");
		return NB_ERR_VALIDATION;
	}
	if (is_srv6_vpn_afi_enabled(bgp, afi)) {
		snprintfrr(errmsg, errmsg_len,
			   "sid vpn per afi is configured; remove it before sid export");
		return NB_ERR_VALIDATION;
	}
	if (is_srv6_vpn_vrf_enabled(bgp)) {
		snprintfrr(errmsg, errmsg_len,
			   "sid vpn per-vrf is configured; remove it before sid export");
		return NB_ERR_VALIDATION;
	}
	if (mode == BGP_NB_SID_NONE)
		return NB_OK;

	/* Mode changes require unconfigure first (classic CLI semantics). */
	if (is_srv6_unicast_enabled(bgp, afi)) {
		bool cur_auto = CHECK_FLAG(bgp->srv6_unicast[afi].flags, SRV6_POLICY_FLAG_SID_AUTO);
		bool cur_explicit = !!bgp->srv6_unicast[afi].sid_explicit;
		uint32_t cur_idx = bgp->srv6_unicast[afi].sid_index;
		bool same_mode = (mode == BGP_NB_SID_AUTO && cur_auto) ||
				 (mode == BGP_NB_SID_INDEX && cur_idx != 0 && idx == cur_idx) ||
				 (mode == BGP_NB_SID_EXPLICIT && cur_explicit &&
				  IPV6_ADDR_SAME(explicit, bgp->srv6_unicast[afi].sid_explicit));

		if (!same_mode && !((mode == BGP_NB_SID_INDEX && cur_idx != 0) ||
				    (mode == BGP_NB_SID_AUTO && cur_auto) ||
				    (mode == BGP_NB_SID_EXPLICIT && cur_explicit))) {
			/* Different mode family */
			if (cur_idx != 0 && mode != BGP_NB_SID_INDEX) {
				snprintfrr(errmsg, errmsg_len,
					   "it's already configured as idx-mode");
				return NB_ERR_VALIDATION;
			}
			if (cur_explicit && mode != BGP_NB_SID_EXPLICIT) {
				snprintfrr(errmsg, errmsg_len,
					   "it's already configured as explicit-mode");
				return NB_ERR_VALIDATION;
			}
			if (cur_auto && mode != BGP_NB_SID_AUTO) {
				snprintfrr(errmsg, errmsg_len,
					   "it's already configured as auto-mode");
				return NB_ERR_VALIDATION;
			}
		}

		if (same_mode || (mode == BGP_NB_SID_INDEX && cur_idx != 0) ||
		    (mode == BGP_NB_SID_AUTO && cur_auto) ||
		    (mode == BGP_NB_SID_EXPLICIT && cur_explicit)) {
			bool cur_dt46 = CHECK_FLAG(bgp->srv6_unicast[afi].flags,
						   SRV6_POLICY_FLAG_BEHAVIOR_DT46);

			if (dt46 != cur_dt46) {
				snprintfrr(errmsg, errmsg_len,
					   "SID export is already configured; unconfigure it first to change behavior");
				return NB_ERR_VALIDATION;
			}
		}
	}

	if (!dt46)
		return NB_OK;

	other_afi = (afi == AFI_IP) ? AFI_IP6 : AFI_IP;
	if (!is_srv6_unicast_dt46_enabled(bgp, other_afi))
		return NB_OK;

	{
		bool other_auto = CHECK_FLAG(bgp->srv6_unicast[other_afi].flags,
					     SRV6_POLICY_FLAG_SID_AUTO);
		uint32_t other_index = bgp->srv6_unicast[other_afi].sid_index;
		bool other_explicit = !!bgp->srv6_unicast[other_afi].sid_explicit;

		if ((mode == BGP_NB_SID_AUTO) != other_auto ||
		    (mode == BGP_NB_SID_INDEX) != (other_index != 0) ||
		    (mode == BGP_NB_SID_EXPLICIT) != other_explicit) {
			snprintfrr(errmsg, errmsg_len,
				   "DT46 sid export mode mismatch with %s unicast",
				   afi2str(other_afi));
			return NB_ERR_VALIDATION;
		}
		if (mode == BGP_NB_SID_INDEX && idx != other_index) {
			snprintfrr(errmsg, errmsg_len,
				   "DT46 sid index mismatch with %s unicast (configured as %u)",
				   afi2str(other_afi), other_index);
			return NB_ERR_VALIDATION;
		}
		if (mode == BGP_NB_SID_EXPLICIT && bgp->srv6_unicast[other_afi].sid_explicit &&
		    !IPV6_ADDR_SAME(explicit, bgp->srv6_unicast[other_afi].sid_explicit)) {
			snprintfrr(errmsg, errmsg_len,
				   "DT46 explicit SID value mismatch with %s unicast",
				   afi2str(other_afi));
			return NB_ERR_VALIDATION;
		}
	}
	return NB_OK;
}

static int bgp_nb_sid_export_apply(struct bgp *bgp, afi_t afi, const struct lyd_node *cont)
{
	enum bgp_nb_sid_export_mode mode;
	uint32_t idx;
	struct in6_addr explicit;
	bool dt46;
	const char *rmap;
	bool was_enabled = is_srv6_unicast_enabled(bgp, afi);
	bool same_alloc;

	bgp_nb_sid_export_read(cont, &mode, &idx, &explicit, &dt46, &rmap);

	if (mode == BGP_NB_SID_NONE) {
		bgp_nb_sid_export_clear(bgp, afi);
		return NB_OK;
	}

	same_alloc = (mode == BGP_NB_SID_AUTO &&
		      CHECK_FLAG(bgp->srv6_unicast[afi].flags, SRV6_POLICY_FLAG_SID_AUTO)) ||
		     (mode == BGP_NB_SID_INDEX && bgp->srv6_unicast[afi].sid_index != 0) ||
		     (mode == BGP_NB_SID_EXPLICIT && bgp->srv6_unicast[afi].sid_explicit);

	if (was_enabled && same_alloc) {
		/* Same mode family: only route-map may change (classic). */
		const char *cur = bgp->srv6_unicast[afi].rmap_name;

		if ((!rmap && !cur) || (rmap && cur && strmatch(rmap, cur)))
			return NB_OK;

		if (cur) {
			route_map_counter_decrement(route_map_lookup_by_name(cur));
			XFREE(MTYPE_ROUTE_MAP_NAME, bgp->srv6_unicast[afi].rmap_name);
			bgp->srv6_unicast[afi].rmap_name = NULL;
		}
		if (rmap) {
			bgp->srv6_unicast[afi].rmap_name = XSTRDUP(MTYPE_ROUTE_MAP_NAME, rmap);
			route_map_counter_increment(route_map_lookup_by_name(rmap));
		}
		bgp_srv6_unicast_announce(bgp, afi);
		return NB_OK;
	}

	if (rmap) {
		if (bgp->srv6_unicast[afi].rmap_name) {
			route_map_counter_decrement(
				route_map_lookup_by_name(bgp->srv6_unicast[afi].rmap_name));
			XFREE(MTYPE_ROUTE_MAP_NAME, bgp->srv6_unicast[afi].rmap_name);
		}
		bgp->srv6_unicast[afi].rmap_name = XSTRDUP(MTYPE_ROUTE_MAP_NAME, rmap);
		route_map_counter_increment(route_map_lookup_by_name(rmap));
	}

	if (mode == BGP_NB_SID_AUTO) {
		SET_FLAG(bgp->srv6_unicast[afi].flags, SRV6_POLICY_FLAG_SID_AUTO);
	} else if (mode == BGP_NB_SID_INDEX) {
		bgp->srv6_unicast[afi].sid_index = idx;
	} else if (mode == BGP_NB_SID_EXPLICIT) {
		if (!bgp->srv6_unicast[afi].sid_explicit)
			bgp->srv6_unicast[afi].sid_explicit = XCALLOC(MTYPE_BGP_SRV6_SID,
								      sizeof(struct in6_addr));
		IPV6_ADDR_COPY(bgp->srv6_unicast[afi].sid_explicit, &explicit);
	}

	if (dt46)
		SET_FLAG(bgp->srv6_unicast[afi].flags, SRV6_POLICY_FLAG_BEHAVIOR_DT46);
	else
		UNSET_FLAG(bgp->srv6_unicast[afi].flags, SRV6_POLICY_FLAG_BEHAVIOR_DT46);

	bgp_srv6_unicast_ensure_afi_sid(bgp, afi);
	return NB_OK;
}

static int bgp_nb_sid_export_from_dnode(const struct lyd_node *dnode, enum nb_event event,
					char *errmsg, size_t errmsg_len)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	const struct lyd_node *cont;
	enum bgp_nb_sid_export_mode mode;
	uint32_t idx;
	struct in6_addr explicit;
	bool dt46;
	const char *rmap;

	cont = yang_dnode_get_parent(dnode, "sid-export");
	bgp_nb_sid_export_read(cont, &mode, &idx, &explicit, &dt46, &rmap);

	switch (event) {
	case NB_EV_VALIDATE:
		bgp = nb_running_get_entry(dnode, NULL, false);
		if (!bgp || !bgp_nb_dnode_afi_safi(dnode, &afi, &safi))
			return NB_OK;
		return bgp_nb_sid_export_validate(bgp, afi, mode, idx, &explicit, dt46, errmsg,
						  errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_get_entry(dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	return bgp_nb_sid_export_apply(bgp, afi, cont);
}

int bgp_nb_sid_export_index_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_sid_export_from_dnode(args->dnode, args->event, args->errmsg,
					    args->errmsg_len);
}

int bgp_nb_sid_export_index_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	const struct lyd_node *cont;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	/*
	 * Mode switch in the same transaction: another allocation leaf is
	 * present; let that leaf's apply own the state.
	 */
	cont = yang_dnode_get_parent(args->dnode, "sid-export");
	if (cont &&
	    (yang_dnode_exists(cont, "./sid-auto") || yang_dnode_exists(cont, "./sid-explicit")))
		return NB_OK;

	bgp_nb_sid_export_clear(bgp, afi);
	return NB_OK;
}

int bgp_nb_sid_export_auto_create(struct nb_cb_create_args *args)
{
	return bgp_nb_sid_export_from_dnode(args->dnode, args->event, args->errmsg,
					    args->errmsg_len);
}

int bgp_nb_sid_export_auto_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	const struct lyd_node *cont;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	cont = yang_dnode_get_parent(args->dnode, "sid-export");
	if (cont &&
	    (yang_dnode_exists(cont, "./sid-index") || yang_dnode_exists(cont, "./sid-explicit")))
		return NB_OK;

	bgp_nb_sid_export_clear(bgp, afi);
	return NB_OK;
}

int bgp_nb_sid_export_explicit_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_sid_export_from_dnode(args->dnode, args->event, args->errmsg,
					    args->errmsg_len);
}

int bgp_nb_sid_export_explicit_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	const struct lyd_node *cont;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	cont = yang_dnode_get_parent(args->dnode, "sid-export");
	if (cont &&
	    (yang_dnode_exists(cont, "./sid-index") || yang_dnode_exists(cont, "./sid-auto")))
		return NB_OK;

	bgp_nb_sid_export_clear(bgp, afi);
	return NB_OK;
}

int bgp_nb_sid_export_dt46_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_sid_export_from_dnode(args->dnode, args->event, args->errmsg,
					    args->errmsg_len);
}

int bgp_nb_sid_export_dt46_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	const struct lyd_node *cont;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	/* Allocation may already be cleared by a sibling destroy. */
	if (!is_srv6_unicast_enabled(bgp, afi))
		return NB_OK;

	UNSET_FLAG(bgp->srv6_unicast[afi].flags, SRV6_POLICY_FLAG_BEHAVIOR_DT46);
	cont = yang_dnode_get_parent(args->dnode, "sid-export");
	if (cont &&
	    (yang_dnode_exists(cont, "./sid-auto") || yang_dnode_exists(cont, "./sid-index") ||
	     yang_dnode_exists(cont, "./sid-explicit")))
		bgp_srv6_unicast_ensure_afi_sid(bgp, afi);
	return NB_OK;
}

int bgp_nb_sid_export_rmap_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_sid_export_from_dnode(args->dnode, args->event, args->errmsg,
					    args->errmsg_len);
}

int bgp_nb_sid_export_rmap_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	if (!bgp->srv6_unicast[afi].rmap_name)
		return NB_OK;

	route_map_counter_decrement(route_map_lookup_by_name(bgp->srv6_unicast[afi].rmap_name));
	XFREE(MTYPE_ROUTE_MAP_NAME, bgp->srv6_unicast[afi].rmap_name);
	bgp->srv6_unicast[afi].rmap_name = NULL;

	if (is_srv6_unicast_enabled(bgp, afi))
		bgp_srv6_unicast_announce(bgp, afi);
	return NB_OK;
}

void bgp_nb_cli_show_sid_export(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const struct lyd_node *cont = yang_dnode_get_parent(dnode, "sid-export");
	enum bgp_nb_sid_export_mode mode;
	uint32_t idx;
	struct in6_addr explicit;
	bool dt46;
	const char *rmap;
	char buf[INET6_ADDRSTRLEN];

	bgp_nb_sid_export_read(cont, &mode, &idx, &explicit, &dt46, &rmap);
	if (mode == BGP_NB_SID_NONE)
		return;

	/* Print once from the allocation leaf only. */
	if (mode == BGP_NB_SID_AUTO && !strmatch(dnode->schema->name, "sid-auto"))
		return;
	if (mode == BGP_NB_SID_INDEX && !strmatch(dnode->schema->name, "sid-index"))
		return;
	if (mode == BGP_NB_SID_EXPLICIT && !strmatch(dnode->schema->name, "sid-explicit"))
		return;

	if (mode == BGP_NB_SID_AUTO)
		vty_out(vty, "  sid export auto");
	else if (mode == BGP_NB_SID_EXPLICIT) {
		inet_ntop(AF_INET6, &explicit, buf, sizeof(buf));
		vty_out(vty, "  sid export explicit %s", buf);
	} else
		vty_out(vty, "  sid export %u", idx);

	if (dt46)
		vty_out(vty, " behavior dt46");
	if (rmap)
		vty_out(vty, " route-map %s", rmap);
	vty_out(vty, "\n");
}

/*
 * segment-routing srv6
 */
int bgp_nb_srv6_locator_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *name;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
		bgp = nb_running_get_entry(args->dnode, NULL, false);
		if (!bgp)
			return NB_OK;
		name = yang_dnode_get_string(args->dnode, NULL);
		if (strlen(bgp->srv6_locator_name) > 0 && !strmatch(name, bgp->srv6_locator_name)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "srv6 locator is already configured");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp)
		return NB_ERR_NOT_FOUND;

	name = yang_dnode_get_string(args->dnode, NULL);
	/*
	 * A previous apply may have stored the name while zebra was down.
	 * APPLY failures are not rolled back, so a later apply of the same
	 * name must ask zebra again until the locator object exists.
	 */
	if (strmatch(name, bgp->srv6_locator_name) && bgp->srv6_locator)
		return NB_OK;

	if (!strmatch(name, bgp->srv6_locator_name)) {
		bgp_srv6_sids_unset(bgp);
		snprintfrr(bgp->srv6_locator_name, sizeof(bgp->srv6_locator_name), "%s", name);
	}
	ret = bgp_zebra_srv6_manager_get_locator(name);
	if (ret < 0) {
		snprintfrr(args->errmsg, args->errmsg_len, "failed to get srv6 locator %s", name);
		return NB_ERR_RESOURCE;
	}
	return NB_OK;
}

int bgp_nb_srv6_locator_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp)
		return NB_OK;

	if (bgp_srv6_locator_unset(bgp) < 0) {
		snprintfrr(args->errmsg, args->errmsg_len, "failed to unset srv6 locator");
		return NB_ERR_RESOURCE;
	}
	return NB_OK;
}

int bgp_nb_srv6_encap_behavior_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *val;
	enum srv6_headend_behavior behavior;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp)
		return NB_ERR_NOT_FOUND;

	val = yang_dnode_get_string(args->dnode, NULL);
	if (strmatch(val, "h-encaps-red"))
		behavior = SRV6_HEADEND_BEHAVIOR_H_ENCAPS_RED;
	else
		behavior = SRV6_HEADEND_BEHAVIOR_H_ENCAPS;

	if (behavior == bgp->srv6_encap_behavior)
		return NB_OK;

	bgp->srv6_encap_behavior = behavior;
	bgp_segment_routing_srv6_hencaps_refresh(bgp);
	return NB_OK;
}

int bgp_nb_srv6_encap_behavior_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp)
		return NB_OK;

	if (bgp->srv6_encap_behavior == SRV6_HEADEND_BEHAVIOR_H_ENCAPS)
		return NB_OK;

	bgp->srv6_encap_behavior = SRV6_HEADEND_BEHAVIOR_H_ENCAPS;
	bgp_segment_routing_srv6_hencaps_refresh(bgp);
	return NB_OK;
}

int bgp_nb_srv6_only_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	bool enable;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp)
		return NB_ERR_NOT_FOUND;

	enable = yang_dnode_get_bool(args->dnode, NULL);
	if (enable == bgp->srv6_only)
		return NB_OK;

	bgp_srv6_only_change(bgp, enable);
	return NB_OK;
}

int bgp_nb_srv6_only_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp)
		return NB_OK;

	/* YANG default is true; restoring default matches leaf destroy. */
	if (bgp->srv6_only)
		return NB_OK;
	bgp_srv6_only_change(bgp, true);
	return NB_OK;
}

void bgp_nb_cli_show_srv6(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, " !\n segment-routing srv6\n");
}

void bgp_nb_cli_show_srv6_end(struct vty *vty, const struct lyd_node *dnode)
{
	vty_out(vty, " exit\n");
}

void bgp_nb_cli_show_srv6_locator(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, "  locator %s\n", yang_dnode_get_string(dnode, NULL));
}

void bgp_nb_cli_show_srv6_encap(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const char *val = yang_dnode_get_string(dnode, NULL);

	if (strmatch(val, "h-encaps") && !show_defaults)
		return;

	vty_out(vty, "  encap-behavior %s\n",
		strmatch(val, "h-encaps-red") ? "H_Encaps_Red" : "H_Encaps");
}

void bgp_nb_cli_show_srv6_only(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	bool only = yang_dnode_get_bool(dnode, NULL);

	if (only && !show_defaults)
		return;
	if (only)
		vty_out(vty, "  srv6-only\n");
	else
		vty_out(vty, "  no srv6-only\n");
}

/*
 * link-state: distribute bgp-fabric-link-state
 */
static int bgp_nb_ls_fabric_enable(struct bgp *bgp, uint64_t instance_id, char *errmsg,
				   size_t errmsg_len)
{
	if (!bgp->ls_info) {
		snprintfrr(errmsg, errmsg_len, "BGP-LS not initialized");
		return NB_ERR_RESOURCE;
	}

	if (bgp->ls_info->enable_distribution && bgp->ls_info->instance_id == instance_id)
		return NB_OK;

	if (bgp->ls_info->enable_distribution && bgp->ls_info->instance_id != instance_id)
		bgp_ls_withdraw_all(bgp);

	bgp->ls_info->instance_id = instance_id;
	bgp->ls_info->enable_distribution = true;

	bgp_redist_add(bgp, AFI_IP6, ZEBRA_ROUTE_ALL, 0);
	if (bgp_redistribute_set(bgp, AFI_IP6, ZEBRA_ROUTE_ALL, 0, false) != CMD_SUCCESS)
		zlog_warn("%s: failed to subscribe to IPv6 ZEBRA_ROUTE_ALL redistribution",
			  __func__);

	if (bgp_zclient && bgp_zclient->sock >= 0)
		bgp_zebra_srv6_manager_get_locator(NULL);

	if (bgp_ls_export_bgp_topology(bgp) != 0) {
		snprintfrr(errmsg, errmsg_len, "Failed to export BGP topology");
		return NB_ERR_RESOURCE;
	}
	return NB_OK;
}

static void bgp_nb_ls_fabric_disable(struct bgp *bgp)
{
	if (!bgp->ls_info || !bgp->ls_info->enable_distribution)
		return;

	bgp_redistribute_unset(bgp, AFI_IP6, ZEBRA_ROUTE_ALL, 0);
	bgp->ls_info->enable_distribution = false;
	bgp->ls_info->instance_id = 0;
	bgp_ls_withdraw_all(bgp);
}

int bgp_nb_ls_fabric_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	uint64_t instance_id = 0;

	switch (args->event) {
	case NB_EV_VALIDATE:
		bgp = nb_running_get_entry(args->dnode, NULL, false);
		if (bgp && !bgp->ls_info) {
			snprintfrr(args->errmsg, args->errmsg_len, "BGP-LS not initialized");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp)
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_exists(args->dnode, "./instance-id"))
		instance_id = yang_dnode_get_uint64(args->dnode, "./instance-id");

	return bgp_nb_ls_fabric_enable(bgp, instance_id, args->errmsg, args->errmsg_len);
}

int bgp_nb_ls_fabric_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp)
		return NB_OK;

	bgp_nb_ls_fabric_disable(bgp);
	return NB_OK;
}

int bgp_nb_ls_fabric_instance_id_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	uint64_t instance_id;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp)
		return NB_ERR_NOT_FOUND;

	instance_id = yang_dnode_get_uint64(args->dnode, NULL);
	return bgp_nb_ls_fabric_enable(bgp, instance_id, args->errmsg, args->errmsg_len);
}

int bgp_nb_ls_fabric_instance_id_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp->ls_info)
		return NB_OK;

	/* Restoring default instance-id 0 while container remains. */
	if (!bgp->ls_info->enable_distribution)
		return NB_OK;

	return bgp_nb_ls_fabric_enable(bgp, 0, args->errmsg, args->errmsg_len);
}

void bgp_nb_cli_show_ls_fabric(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	uint64_t instance_id = 0;

	if (yang_dnode_exists(dnode, "./instance-id"))
		instance_id = yang_dnode_get_uint64(dnode, "./instance-id");

	if (instance_id || show_defaults)
		vty_out(vty, "  distribute bgp-fabric-link-state instance-id %" PRIu64 "\n",
			instance_id);
	else
		vty_out(vty, "  distribute bgp-fabric-link-state\n");
}


/*
 * Sort implied by the candidate remote-as, not the running peer. A
 * peer-group with no remote-as (and no members yet) is INTERNAL: the
 * flag is stored and inherited when a member is bound.
 */
static enum bgp_peer_sort bgp_nb_candidate_peer_sort(const struct lyd_node *dnode)
{
	const struct lyd_node *nbr, *bgp_node;
	const char *as_type;
	as_t local_as, remote_as;

	nbr = yang_dnode_get_parent(dnode, "neighbor");
	if (!nbr)
		nbr = yang_dnode_get_parent(dnode, "unnumbered-neighbor");
	if (!nbr)
		nbr = yang_dnode_get_parent(dnode, "peer-group");
	if (!nbr || !yang_dnode_exists(nbr, "neighbor-remote-as/remote-as-type"))
		return BGP_PEER_INTERNAL;

	as_type = yang_dnode_get_string(nbr, "neighbor-remote-as/remote-as-type");
	if (strmatch(as_type, "internal"))
		return BGP_PEER_IBGP;
	if (strmatch(as_type, "external"))
		return BGP_PEER_EBGP;
	if (!strmatch(as_type, "as-specified") ||
	    !yang_dnode_exists(nbr, "neighbor-remote-as/remote-as"))
		return BGP_PEER_INTERNAL;

	remote_as = yang_dnode_get_uint32(nbr, "neighbor-remote-as/remote-as");
	bgp_node = yang_dnode_get_parent(dnode, "bgp");
	if (!bgp_node || !yang_dnode_exists(bgp_node, "local-as"))
		return BGP_PEER_INTERNAL;
	local_as = yang_dnode_get_uint32(bgp_node, "local-as");
	if (!local_as)
		return BGP_PEER_INTERNAL;

	return local_as == remote_as ? BGP_PEER_IBGP : BGP_PEER_EBGP;
}

static enum bgp_peer_sort bgp_nb_af_flag_sort(const struct lyd_node *dnode)
{
	struct peer *peer;
	enum bgp_peer_sort sort;

	sort = bgp_nb_candidate_peer_sort(dnode);
	if (sort != BGP_PEER_INTERNAL)
		return sort;

	peer = bgp_nb_config_peer(dnode);
	if (!peer)
		return BGP_PEER_INTERNAL;
	if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP) && peer_sort(peer) == BGP_PEER_INTERNAL)
		return BGP_PEER_INTERNAL;
	return peer_sort(peer);
}

static int bgp_nb_peer_af_flag_validate(struct nb_cb_modify_args *args, uint64_t flag)
{
	enum bgp_peer_sort sort;

	sort = bgp_nb_af_flag_sort(args->dnode);
	if (sort == BGP_PEER_INTERNAL || sort == BGP_PEER_UNSPECIFIED)
		return NB_OK;

	if (CHECK_FLAG(flag, PEER_FLAG_REFLECTOR_CLIENT) && sort != BGP_PEER_IBGP) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   "Invalid command. Not an internal neighbor");
		return NB_ERR_VALIDATION;
	}
	if (CHECK_FLAG(flag, PEER_FLAG_REMOVE_PRIVATE_AS) && sort == BGP_PEER_IBGP) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   "remove-private-AS cannot be configured for IBGP peers");
		return NB_ERR_VALIDATION;
	}
	if (CHECK_FLAG(flag, PEER_FLAG_AS_OVERRIDE) && sort == BGP_PEER_IBGP) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   "as-override cannot be configured for IBGP peers");
		return NB_ERR_VALIDATION;
	}
	return NB_OK;
}

static int bgp_nb_peer_af_flag_modify(struct nb_cb_modify_args *args, uint64_t flag)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_nb_peer_af_flag_validate(args, flag);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL))
		ret = peer_af_flag_set(peer, afi, safi, flag);
	else
		ret = peer_af_flag_unset(peer, afi, safi, flag);
	if (ret < 0)
		zlog_warn("%s: flag 0x%" PRIx64 " was not applied (%d)", __func__, flag, ret);
	return NB_OK;
}

int bgp_nb_peer_afi_safi_create(struct nb_cb_create_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	const char *name;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	name = yang_dnode_get_string(args->dnode, "./afi-safi-name");
	yang_afi_safi_identity2value(name, &afi, &safi);

	if (yang_dnode_exists(args->dnode, "./enabled") &&
	    yang_dnode_get_bool(args->dnode, "./enabled"))
		peer_activate(peer, afi, safi);

	return NB_OK;
}

int bgp_nb_peer_afi_safi_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	const char *name;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_OK;

	name = yang_dnode_get_string(args->dnode, "./afi-safi-name");
	yang_afi_safi_identity2value(name, &afi, &safi);
	peer_deactivate(peer, afi, safi);
	return NB_OK;
}

int bgp_nb_peer_af_enabled_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL)) {
		if (peer_activate(peer, afi, safi) < 0)
			return NB_ERR_RESOURCE;
	} else {
		if (peer_deactivate(peer, afi, safi) < 0)
			return NB_ERR_RESOURCE;
	}
	return NB_OK;
}

int bgp_nb_peer_af_enabled_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	peer_deactivate(peer, afi, safi);
	return NB_OK;
}

void bgp_nb_cli_show_peer_af_enabled(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s activate\n", bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, " no neighbor %s activate\n", bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_af_soft_reconfig_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_flag_modify(args, PEER_FLAG_SOFT_RECONFIG);
}

void bgp_nb_cli_show_peer_af_soft_reconfig(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s soft-reconfiguration inbound\n",
			bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, " no neighbor %s soft-reconfiguration inbound\n",
			bgp_nb_config_peer_name(dnode));
}

static void bgp_nb_peer_af_encap_clear(struct peer *peer, afi_t afi, safi_t safi)
{
	peer_af_flag_unset(peer, afi, safi, PEER_FLAG_CONFIG_ENCAPSULATION_SRV6);
	peer_af_flag_unset(peer, afi, safi, PEER_FLAG_CONFIG_ENCAPSULATION_SRV6_RELAX);
	peer_af_flag_unset(peer, afi, safi, PEER_FLAG_CONFIG_ENCAPSULATION_MPLS);
}

static uint64_t bgp_nb_peer_af_encap_flag(const char *val)
{
	if (strmatch(val, "mpls"))
		return PEER_FLAG_CONFIG_ENCAPSULATION_MPLS;
	if (strmatch(val, "srv6-relax"))
		return PEER_FLAG_CONFIG_ENCAPSULATION_SRV6_RELAX;
	return PEER_FLAG_CONFIG_ENCAPSULATION_SRV6;
}

int bgp_nb_peer_af_encapsulation_create(struct nb_cb_create_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	const char *val;
	uint64_t flag;
	const struct lyd_node *encap, *entry;

	switch (args->event) {
	case NB_EV_VALIDATE: {
		bool has_srv6 = false, has_relax = false;

		peer = bgp_nb_config_peer(args->dnode);
		if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
			return NB_OK;

		encap = yang_dnode_get_parent(args->dnode, "encapsulation");
		if (encap) {
			LY_LIST_FOR (lyd_child(encap), entry) {
				const char *v;

				if (!strmatch(entry->schema->name, "type"))
					continue;
				v = yang_dnode_get_string(entry, NULL);
				if (strmatch(v, "srv6"))
					has_srv6 = true;
				else if (strmatch(v, "srv6-relax"))
					has_relax = true;
			}
		}

		/*
		 * Unicast CLI treats srv6 and srv6-relax as mutually exclusive
		 * and requires unconfigure before switching. Candidate may
		 * already contain both during a bad edit — reject.
		 */
		if (safi == SAFI_UNICAST && has_srv6 && has_relax) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "Peer is already configured, unset it first");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	val = yang_dnode_get_string(args->dnode, NULL);
	flag = bgp_nb_peer_af_encap_flag(val);

	if (peergroup_af_flag_check(peer, afi, safi, flag))
		return NB_OK;

	/* srv6 and srv6-relax replace each other; mpls is independent. */
	if (flag == PEER_FLAG_CONFIG_ENCAPSULATION_SRV6)
		peer_af_flag_unset(peer, afi, safi, PEER_FLAG_CONFIG_ENCAPSULATION_SRV6_RELAX);
	else if (flag == PEER_FLAG_CONFIG_ENCAPSULATION_SRV6_RELAX)
		peer_af_flag_unset(peer, afi, safi, PEER_FLAG_CONFIG_ENCAPSULATION_SRV6);

	if (peer_af_flag_set(peer, afi, safi, flag) < 0)
		return NB_ERR_RESOURCE;
	return NB_OK;
}

int bgp_nb_peer_af_encapsulation_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	const char *val;
	uint64_t flag;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	/*
	 * Leaf-list destroy removes one value. Container/list destroy of the
	 * parent may still call us without a typed value — clear all.
	 */
	if (args->dnode->schema->nodetype == LYS_LEAFLIST) {
		val = yang_dnode_get_string(args->dnode, NULL);
		flag = bgp_nb_peer_af_encap_flag(val);
		peer_af_flag_unset(peer, afi, safi, flag);
	} else
		bgp_nb_peer_af_encap_clear(peer, afi, safi);
	return NB_OK;
}

void bgp_nb_cli_show_peer_af_encapsulation(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	const char *val = yang_dnode_get_string(dnode, NULL);
	const char *cli;

	if (strmatch(val, "mpls"))
		cli = "encapsulation-mpls";
	else if (strmatch(val, "srv6-relax"))
		cli = "encapsulation-srv6-relax";
	else
		cli = "encapsulation-srv6";

	vty_out(vty, " neighbor %s %s\n", bgp_nb_config_peer_name(dnode), cli);
}

int bgp_nb_peer_af_nexthop_self_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_flag_modify(args, PEER_FLAG_NEXTHOP_SELF);
}

void bgp_nb_cli_show_peer_af_nexthop_self(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s next-hop-self\n", bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, " no neighbor %s next-hop-self\n", bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_af_nexthop_self_force_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_flag_modify(args, PEER_FLAG_FORCE_NEXTHOP_SELF);
}

void bgp_nb_cli_show_peer_af_nexthop_self_force(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s next-hop-self force\n", bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, " no neighbor %s next-hop-self force\n",
			bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_af_aspath_unchanged_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_flag_modify(args, PEER_FLAG_AS_PATH_UNCHANGED);
}

static void bgp_nb_cli_show_attr_unchanged(struct vty *vty, const struct lyd_node *dnode,
					   const char *self)
{
	const struct lyd_node *parent;
	bool aspath, nexthop, med;

	if (!yang_dnode_get_bool(dnode, NULL))
		return;

	parent = yang_dnode_get_parent(dnode, "attr-unchanged");
	if (!parent)
		return;

	aspath = yang_dnode_exists(parent, "as-path-unchanged") &&
		 yang_dnode_get_bool(parent, "as-path-unchanged");
	nexthop = yang_dnode_exists(parent, "next-hop-unchanged") &&
		  yang_dnode_get_bool(parent, "next-hop-unchanged");
	med = yang_dnode_exists(parent, "med-unchanged") &&
	      yang_dnode_get_bool(parent, "med-unchanged");

	/*
	 * The three leaves are one CLI command. Emit it once, from the last
	 * enabled keyword, so frr-reload does not keep only the last line.
	 */
	if (strmatch(self, "as-path") && (nexthop || med))
		return;
	if (strmatch(self, "next-hop") && med)
		return;

	vty_out(vty, " neighbor %s attribute-unchanged%s%s%s\n", bgp_nb_config_peer_name(dnode),
		aspath ? " as-path" : "", nexthop ? " next-hop" : "", med ? " med" : "");
}

void bgp_nb_cli_show_peer_af_aspath_unchanged(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults)
{
	bgp_nb_cli_show_attr_unchanged(vty, dnode, "as-path");
}

int bgp_nb_peer_af_nexthop_unchanged_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_flag_modify(args, PEER_FLAG_NEXTHOP_UNCHANGED);
}

void bgp_nb_cli_show_peer_af_nexthop_unchanged(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults)
{
	bgp_nb_cli_show_attr_unchanged(vty, dnode, "next-hop");
}

int bgp_nb_peer_af_med_unchanged_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_flag_modify(args, PEER_FLAG_MED_UNCHANGED);
}

void bgp_nb_cli_show_peer_af_med_unchanged(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	bgp_nb_cli_show_attr_unchanged(vty, dnode, "med");
}

int bgp_nb_peer_af_as_override_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_flag_modify(args, PEER_FLAG_AS_OVERRIDE);
}

void bgp_nb_cli_show_peer_af_as_override(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s as-override\n", bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_af_remove_private_as_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_flag_modify(args, PEER_FLAG_REMOVE_PRIVATE_AS);
}

void bgp_nb_cli_show_peer_af_remove_private_as(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s remove-private-AS\n", bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_af_remove_private_as_all_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_flag_modify(args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL);
}

void bgp_nb_cli_show_peer_af_remove_private_as_all(struct vty *vty, const struct lyd_node *dnode,
						   bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s remove-private-AS all\n",
			bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_af_remove_private_as_replace_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_flag_modify(args, PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE);
}

void bgp_nb_cli_show_peer_af_remove_private_as_replace(struct vty *vty,
						       const struct lyd_node *dnode,
						       bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s remove-private-AS replace-AS\n",
			bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_af_remove_private_as_all_replace_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_flag_modify(args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE);
}

void bgp_nb_cli_show_peer_af_remove_private_as_all_replace(struct vty *vty,
							   const struct lyd_node *dnode,
							   bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s remove-private-AS all replace-AS\n",
			bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_af_reflector_client_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_flag_modify(args, PEER_FLAG_REFLECTOR_CLIENT);
}

void bgp_nb_cli_show_peer_af_reflector_client(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s route-reflector-client\n",
			bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_af_rserver_client_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_flag_modify(args, PEER_FLAG_RSERVER_CLIENT);
}

void bgp_nb_cli_show_peer_af_rserver_client(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s route-server-client\n", bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_af_weight_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	uint16_t weight;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	weight = yang_dnode_get_uint16(args->dnode, NULL);
	if (peer_weight_set(peer, afi, safi, weight) < 0)
		return NB_ERR_RESOURCE;
	return NB_OK;
}

int bgp_nb_peer_af_weight_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	peer_weight_unset(peer, afi, safi);
	return NB_OK;
}

void bgp_nb_cli_show_peer_af_weight(struct vty *vty, const struct lyd_node *dnode,
				    bool show_defaults)
{
	vty_out(vty, " neighbor %s weight %" PRIu16 "\n", bgp_nb_config_peer_name(dnode),
		yang_dnode_get_uint16(dnode, NULL));
}

int bgp_nb_peer_af_send_community_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_flag_modify(args, PEER_FLAG_SEND_COMMUNITY);
}

void bgp_nb_cli_show_peer_af_send_community(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no neighbor %s send-community\n", bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, " neighbor %s send-community\n", bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_af_send_ext_community_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_flag_modify(args, PEER_FLAG_SEND_EXT_COMMUNITY);
}

void bgp_nb_cli_show_peer_af_send_ext_community(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no neighbor %s send-community extended\n",
			bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, " neighbor %s send-community extended\n",
			bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_af_send_large_community_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_flag_modify(args, PEER_FLAG_SEND_LARGE_COMMUNITY);
}

void bgp_nb_cli_show_peer_af_send_large_community(struct vty *vty, const struct lyd_node *dnode,
						  bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no neighbor %s send-community large\n",
			bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, " neighbor %s send-community large\n", bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_af_send_ext_community_rpki_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_flag_modify(args, PEER_FLAG_SEND_EXT_COMMUNITY_RPKI);
}

void bgp_nb_cli_show_peer_af_send_ext_community_rpki(struct vty *vty, const struct lyd_node *dnode,
						     bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s send-community extended rpki\n",
			bgp_nb_config_peer_name(dnode));
}

static const char *bgp_nb_af_allowas_rmap(const struct lyd_node *dnode)
{
	const struct lyd_node *opts;

	opts = yang_dnode_get_parent(dnode, "as-path-options");
	if (!opts)
		return NULL;
	if (!yang_dnode_exists(opts, "./allowas-in-route-map"))
		return NULL;
	return yang_dnode_get_string(opts, "./allowas-in-route-map");
}

int bgp_nb_peer_af_allow_own_as_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	uint8_t allow_num;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	allow_num = yang_dnode_get_uint8(args->dnode, NULL);
	if (peer_allowas_in_set(peer, afi, safi, allow_num, false,
				bgp_nb_af_allowas_rmap(args->dnode)) < 0)
		return NB_ERR_RESOURCE;
	return NB_OK;
}

int bgp_nb_peer_af_allow_own_as_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	peer_allowas_in_unset(peer, afi, safi);
	return NB_OK;
}

void bgp_nb_cli_show_peer_af_allow_own_as(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults)
{
	const char *rmap = bgp_nb_af_allowas_rmap(dnode);
	uint8_t num = yang_dnode_get_uint8(dnode, NULL);

	if (rmap) {
		if (num == BGP_ALLOWAS_IN_DEFAULT)
			vty_out(vty, " neighbor %s allowas-in route-map %s\n",
				bgp_nb_config_peer_name(dnode), rmap);
		else
			vty_out(vty, " neighbor %s allowas-in route-map %s %u\n",
				bgp_nb_config_peer_name(dnode), rmap, num);
	} else if (num == BGP_ALLOWAS_IN_DEFAULT) {
		vty_out(vty, " neighbor %s allowas-in\n", bgp_nb_config_peer_name(dnode));
	} else {
		vty_out(vty, " neighbor %s allowas-in %u\n", bgp_nb_config_peer_name(dnode), num);
	}
}

int bgp_nb_peer_af_allow_own_origin_as_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	if (!yang_dnode_get_bool(args->dnode, NULL)) {
		peer_allowas_in_unset(peer, afi, safi);
		return NB_OK;
	}

	if (peer_allowas_in_set(peer, afi, safi, 0, true, bgp_nb_af_allowas_rmap(args->dnode)) < 0)
		return NB_ERR_RESOURCE;
	return NB_OK;
}

int bgp_nb_peer_af_allow_own_origin_as_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	peer_allowas_in_unset(peer, afi, safi);
	return NB_OK;
}

void bgp_nb_cli_show_peer_af_allow_own_origin_as(struct vty *vty, const struct lyd_node *dnode,
						 bool show_defaults)
{
	const char *rmap;

	if (!yang_dnode_get_bool(dnode, NULL))
		return;

	rmap = bgp_nb_af_allowas_rmap(dnode);
	if (rmap)
		vty_out(vty, " neighbor %s allowas-in route-map %s origin\n",
			bgp_nb_config_peer_name(dnode), rmap);
	else
		vty_out(vty, " neighbor %s allowas-in origin\n", bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_af_allowas_in_rmap_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	const struct lyd_node *opts;
	const char *rmap;
	bool origin;
	int allow_num;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	opts = yang_dnode_get_parent(args->dnode, "as-path-options");
	if (!opts)
		return NB_ERR_NOT_FOUND;

	rmap = yang_dnode_get_string(args->dnode, NULL);
	origin = yang_dnode_exists(opts, "./allow-own-origin-as") &&
		 yang_dnode_get_bool(opts, "./allow-own-origin-as");
	if (origin)
		allow_num = 0;
	else if (yang_dnode_exists(opts, "./allow-own-as"))
		allow_num = yang_dnode_get_uint8(opts, "./allow-own-as");
	else
		allow_num = BGP_ALLOWAS_IN_DEFAULT;

	if (peer_allowas_in_set(peer, afi, safi, allow_num, origin, rmap) < 0)
		return NB_ERR_RESOURCE;
	return NB_OK;
}

int bgp_nb_peer_af_allowas_in_rmap_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	bool origin;
	int allow_num;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	/*
	 * Full 'no ... allowas-in route-map ...' destroys allow-own-as before
	 * this leaf. That unset already cleared PEER_FLAG_ALLOWAS_IN. Do not
	 * consult the old dnode tree for siblings — they still appear present
	 * and a re-set with NULL rmap would wrongly enable unfiltered
	 * allowas-in.
	 *
	 * If only the route-map leaf is removed, allowas-in remains set on the
	 * peer; clear the rmap while keeping the same allow count/origin.
	 */
	if (!CHECK_FLAG(peer->af_flags[afi][safi], PEER_FLAG_ALLOWAS_IN))
		return NB_OK;

	origin = CHECK_FLAG(peer->af_flags[afi][safi], PEER_FLAG_ALLOWAS_IN_ORIGIN);
	allow_num = peer->allowas_in[afi][safi];

	if (peer_allowas_in_set(peer, afi, safi, allow_num, origin, NULL) < 0)
		return NB_ERR_RESOURCE;
	return NB_OK;
}

void bgp_nb_cli_show_peer_af_allowas_in_rmap(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults)
{
	/* Printed with allow-own-as / allow-own-origin-as cli_show. */
}

static const char *bgp_nb_af_default_originate_rmap(const struct lyd_node *dnode)
{
	const struct lyd_node *cont;

	cont = yang_dnode_get_parent(dnode, "default-originate");
	if (!cont)
		return NULL;
	if (!yang_dnode_exists(cont, "./route-map"))
		return NULL;
	return yang_dnode_get_string(cont, "./route-map");
}

int bgp_nb_peer_af_default_originate_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	const char *rmap;
	struct route_map *map = NULL;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	if (!yang_dnode_get_bool(args->dnode, NULL)) {
		peer_default_originate_unset(peer, afi, safi);
		return NB_OK;
	}

	rmap = bgp_nb_af_default_originate_rmap(args->dnode);
	if (rmap)
		map = route_map_lookup_by_name(rmap);
	if (peer_default_originate_set(peer, afi, safi, rmap, map) < 0)
		return NB_ERR_RESOURCE;
	return NB_OK;
}

int bgp_nb_peer_af_default_originate_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	peer_default_originate_unset(peer, afi, safi);
	return NB_OK;
}

void bgp_nb_cli_show_peer_af_default_originate(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults)
{
	const char *rmap;

	if (!yang_dnode_get_bool(dnode, NULL))
		return;

	rmap = bgp_nb_af_default_originate_rmap(dnode);
	if (rmap)
		vty_out(vty, " neighbor %s default-originate route-map %s\n",
			bgp_nb_config_peer_name(dnode), rmap);
	else
		vty_out(vty, " neighbor %s default-originate\n", bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_af_default_originate_rmap_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	const char *rmap;
	struct route_map *map;
	const struct lyd_node *cont;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	cont = yang_dnode_get_parent(args->dnode, "default-originate");
	if (!cont || !yang_dnode_exists(cont, "./originate") ||
	    !yang_dnode_get_bool(cont, "./originate"))
		return NB_OK;

	rmap = yang_dnode_get_string(args->dnode, NULL);
	map = route_map_lookup_by_name(rmap);
	if (peer_default_originate_set(peer, afi, safi, rmap, map) < 0)
		return NB_ERR_RESOURCE;
	return NB_OK;
}

int bgp_nb_peer_af_default_originate_rmap_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	const struct lyd_node *cont;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	cont = yang_dnode_get_parent(args->dnode, "default-originate");
	if (!cont || !yang_dnode_exists(cont, "./originate") ||
	    !yang_dnode_get_bool(cont, "./originate"))
		return NB_OK;

	if (peer_default_originate_set(peer, afi, safi, NULL, NULL) < 0)
		return NB_ERR_RESOURCE;
	return NB_OK;
}

void bgp_nb_cli_show_peer_af_default_originate_rmap(struct vty *vty, const struct lyd_node *dnode,
						    bool show_defaults)
{
	/* Printed with originate cli_show. */
}

static int bgp_nb_peer_af_named_filter_modify(struct nb_cb_modify_args *args, int direct,
					      int (*set_fn)(struct peer *, afi_t, safi_t, int,
							    const char *),
					      const char *conflict)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	const char *name;

	switch (args->event) {
	case NB_EV_VALIDATE:
		/*
		 * The other list may be created in this same candidate, so
		 * read the candidate rather than the live peer filter.
		 */
		if (conflict && yang_dnode_exists(args->dnode, conflict)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "Prefix/distribute list can not co-exist");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	name = yang_dnode_get_string(args->dnode, NULL);
	if (set_fn(peer, afi, safi, direct, name) < 0)
		return NB_ERR_RESOURCE;
	return NB_OK;
}

static int bgp_nb_peer_af_named_filter_destroy(struct nb_cb_destroy_args *args, int direct,
					       int (*unset_fn)(struct peer *, afi_t, safi_t, int))
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	unset_fn(peer, afi, safi, direct);
	return NB_OK;
}

int bgp_nb_peer_af_plist_import_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_named_filter_modify(args, FILTER_IN, peer_prefix_list_set,
						  "../access-list-import");
}

int bgp_nb_peer_af_plist_import_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_peer_af_named_filter_destroy(args, FILTER_IN, peer_prefix_list_unset);
}

void bgp_nb_cli_show_peer_af_plist_import(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults)
{
	vty_out(vty, " neighbor %s prefix-list %s in\n", bgp_nb_config_peer_name(dnode),
		yang_dnode_get_string(dnode, NULL));
}

int bgp_nb_peer_af_plist_export_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_named_filter_modify(args, FILTER_OUT, peer_prefix_list_set,
						  "../access-list-export");
}

int bgp_nb_peer_af_plist_export_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_peer_af_named_filter_destroy(args, FILTER_OUT, peer_prefix_list_unset);
}

void bgp_nb_cli_show_peer_af_plist_export(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults)
{
	vty_out(vty, " neighbor %s prefix-list %s out\n", bgp_nb_config_peer_name(dnode),
		yang_dnode_get_string(dnode, NULL));
}

int bgp_nb_peer_af_access_list_import_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_named_filter_modify(args, FILTER_IN, peer_distribute_set,
						  "../plist-import");
}

int bgp_nb_peer_af_access_list_import_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_peer_af_named_filter_destroy(args, FILTER_IN, peer_distribute_unset);
}

void bgp_nb_cli_show_peer_af_access_list_import(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults)
{
	vty_out(vty, " neighbor %s distribute-list %s in\n", bgp_nb_config_peer_name(dnode),
		yang_dnode_get_string(dnode, NULL));
}

int bgp_nb_peer_af_access_list_export_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_named_filter_modify(args, FILTER_OUT, peer_distribute_set,
						  "../plist-export");
}

int bgp_nb_peer_af_access_list_export_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_peer_af_named_filter_destroy(args, FILTER_OUT, peer_distribute_unset);
}

void bgp_nb_cli_show_peer_af_access_list_export(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults)
{
	vty_out(vty, " neighbor %s distribute-list %s out\n", bgp_nb_config_peer_name(dnode),
		yang_dnode_get_string(dnode, NULL));
}

int bgp_nb_peer_af_aspath_filter_import_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_named_filter_modify(args, FILTER_IN, peer_aslist_set, NULL);
}

int bgp_nb_peer_af_aspath_filter_import_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_peer_af_named_filter_destroy(args, FILTER_IN, peer_aslist_unset);
}

void bgp_nb_cli_show_peer_af_aspath_filter_import(struct vty *vty, const struct lyd_node *dnode,
						  bool show_defaults)
{
	vty_out(vty, " neighbor %s filter-list %s in\n", bgp_nb_config_peer_name(dnode),
		yang_dnode_get_string(dnode, NULL));
}

int bgp_nb_peer_af_aspath_filter_export_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_named_filter_modify(args, FILTER_OUT, peer_aslist_set, NULL);
}

int bgp_nb_peer_af_aspath_filter_export_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_peer_af_named_filter_destroy(args, FILTER_OUT, peer_aslist_unset);
}

void bgp_nb_cli_show_peer_af_aspath_filter_export(struct vty *vty, const struct lyd_node *dnode,
						  bool show_defaults)
{
	vty_out(vty, " neighbor %s filter-list %s out\n", bgp_nb_config_peer_name(dnode),
		yang_dnode_get_string(dnode, NULL));
}

int bgp_nb_peer_af_rmap_import_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	const char *name;
	struct route_map *map;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	name = yang_dnode_get_string(args->dnode, NULL);
	map = route_map_lookup_by_name(name);
	if (peer_route_map_set(peer, afi, safi, RMAP_IN, name, map) < 0)
		return NB_ERR_RESOURCE;
	return NB_OK;
}

int bgp_nb_peer_af_rmap_import_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	peer_route_map_unset(peer, afi, safi, RMAP_IN);
	return NB_OK;
}

void bgp_nb_cli_show_peer_af_rmap_import(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults)
{
	vty_out(vty, " neighbor %s route-map %s in\n", bgp_nb_config_peer_name(dnode),
		yang_dnode_get_string(dnode, NULL));
}

int bgp_nb_peer_af_rmap_export_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	const char *name;
	struct route_map *map;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	name = yang_dnode_get_string(args->dnode, NULL);
	map = route_map_lookup_by_name(name);
	if (peer_route_map_set(peer, afi, safi, RMAP_OUT, name, map) < 0)
		return NB_ERR_RESOURCE;
	return NB_OK;
}

int bgp_nb_peer_af_rmap_export_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	peer_route_map_unset(peer, afi, safi, RMAP_OUT);
	return NB_OK;
}

void bgp_nb_cli_show_peer_af_rmap_export(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults)
{
	vty_out(vty, " neighbor %s route-map %s out\n", bgp_nb_config_peer_name(dnode),
		yang_dnode_get_string(dnode, NULL));
}

int bgp_nb_peer_af_unsuppress_map_export_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	const char *name;
	struct route_map *map;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	name = yang_dnode_get_string(args->dnode, NULL);
	map = route_map_lookup_by_name(name);
	if (peer_unsuppress_map_set(peer, afi, safi, name, map) < 0)
		return NB_ERR_RESOURCE;
	return NB_OK;
}

int bgp_nb_peer_af_unsuppress_map_export_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	peer_unsuppress_map_unset(peer, afi, safi);
	return NB_OK;
}

void bgp_nb_cli_show_peer_af_unsuppress_map_export(struct vty *vty, const struct lyd_node *dnode,
						   bool show_defaults)
{
	vty_out(vty, " neighbor %s unsuppress-map %s\n", bgp_nb_config_peer_name(dnode),
		yang_dnode_get_string(dnode, NULL));
}

static int bgp_nb_peer_af_max_prefix_in_apply(const struct lyd_node *dir)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	uint32_t max;
	uint8_t threshold = MAXIMUM_PREFIX_THRESHOLD_DEFAULT;
	uint16_t restart = 0;
	int warning = 0;
	bool force = false;

	peer = bgp_nb_config_peer(dir);
	if (!peer || !bgp_nb_dnode_afi_safi(dir, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	if (!yang_dnode_exists(dir, "./max-prefixes"))
		return NB_OK;

	max = yang_dnode_get_uint32(dir, "./max-prefixes");
	if (yang_dnode_exists(dir, "./force-check"))
		force = yang_dnode_get_bool(dir, "./force-check");

	if (yang_dnode_exists(dir, "./options/warning-only") &&
	    yang_dnode_get_bool(dir, "./options/warning-only")) {
		warning = 1;
	} else if (yang_dnode_exists(dir, "./options/restart-timer")) {
		restart = yang_dnode_get_uint16(dir, "./options/restart-timer");
	} else if (yang_dnode_exists(dir, "./options/shutdown-threshold-pct")) {
		threshold = yang_dnode_get_uint8(dir, "./options/shutdown-threshold-pct");
	} else if (yang_dnode_exists(dir, "./options/tr-shutdown-threshold-pct")) {
		threshold = yang_dnode_get_uint8(dir, "./options/tr-shutdown-threshold-pct");
		restart = yang_dnode_get_uint16(dir, "./options/tr-restart-timer");
	} else if (yang_dnode_exists(dir, "./options/tw-shutdown-threshold-pct")) {
		threshold = yang_dnode_get_uint8(dir, "./options/tw-shutdown-threshold-pct");
		warning = yang_dnode_exists(dir, "./options/tw-warning-only") &&
			  yang_dnode_get_bool(dir, "./options/tw-warning-only");
	}

	if (peer_maximum_prefix_set(peer, afi, safi, max, threshold, warning, restart, force) < 0)
		return NB_ERR_RESOURCE;
	return NB_OK;
}

static int bgp_nb_peer_af_max_prefix_out_apply(const struct lyd_node *dir)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	uint32_t max;

	peer = bgp_nb_config_peer(dir);
	if (!peer || !bgp_nb_dnode_afi_safi(dir, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	if (!yang_dnode_exists(dir, "./max-prefixes"))
		return NB_OK;

	max = yang_dnode_get_uint32(dir, "./max-prefixes");
	if (peer_maximum_prefix_out_set(peer, afi, safi, max) < 0)
		return NB_ERR_RESOURCE;
	return NB_OK;
}

static const struct lyd_node *bgp_nb_prefix_limit_dir(const struct lyd_node *dnode)
{
	return yang_dnode_get_parent(dnode, "direction-list");
}

int bgp_nb_peer_af_prefix_limit_create(struct nb_cb_create_args *args)
{
	const char *dir;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	dir = yang_dnode_get_string(args->dnode, "./direction");
	if (strmatch(dir, "in"))
		return bgp_nb_peer_af_max_prefix_in_apply(args->dnode);
	return bgp_nb_peer_af_max_prefix_out_apply(args->dnode);
}

int bgp_nb_peer_af_prefix_limit_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	const char *dir;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	dir = yang_dnode_get_string(args->dnode, "./direction");
	if (strmatch(dir, "in"))
		peer_maximum_prefix_unset(peer, afi, safi);
	else
		peer_maximum_prefix_out_unset(peer, afi, safi);
	return NB_OK;
}

int bgp_nb_peer_af_prefix_limit_max_modify(struct nb_cb_modify_args *args)
{
	const struct lyd_node *dir;
	const char *direction;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	dir = bgp_nb_prefix_limit_dir(args->dnode);
	if (!dir)
		return NB_ERR_NOT_FOUND;
	direction = yang_dnode_get_string(dir, "./direction");
	if (strmatch(direction, "in"))
		return bgp_nb_peer_af_max_prefix_in_apply(dir);
	return bgp_nb_peer_af_max_prefix_out_apply(dir);
}

int bgp_nb_peer_af_prefix_limit_force_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_prefix_limit_max_modify(args);
}

int bgp_nb_peer_af_prefix_limit_option_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_prefix_limit_max_modify(args);
}

int bgp_nb_peer_af_prefix_limit_option_destroy(struct nb_cb_destroy_args *args)
{
	const struct lyd_node *dir;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	dir = bgp_nb_prefix_limit_dir(args->dnode);
	if (!dir)
		return NB_OK;

	/* Re-apply remaining options after this leaf is gone. */
	if (strmatch(yang_dnode_get_string(dir, "./direction"), "in"))
		return bgp_nb_peer_af_max_prefix_in_apply(dir);
	return bgp_nb_peer_af_max_prefix_out_apply(dir);
}

void bgp_nb_cli_show_peer_af_prefix_limit_max(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults)
{
	const struct lyd_node *dir = bgp_nb_prefix_limit_dir(dnode);
	const char *direction;
	uint32_t max;
	bool force = false;

	if (!dir)
		return;

	direction = yang_dnode_get_string(dir, "./direction");
	max = yang_dnode_get_uint32(dnode, NULL);
	if (yang_dnode_exists(dir, "./force-check"))
		force = yang_dnode_get_bool(dir, "./force-check");

	if (strmatch(direction, "out")) {
		vty_out(vty, " neighbor %s maximum-prefix-out %u\n",
			bgp_nb_config_peer_name(dnode), max);
		return;
	}

	/*
	 * The neighbor name can be an arbitrarily long peer-group name, so
	 * emit the line piecewise instead of accumulating into a fixed
	 * size buffer.
	 */
	vty_out(vty, " neighbor %s maximum-prefix %u", bgp_nb_config_peer_name(dnode), max);

	if (yang_dnode_exists(dir, "./options/tw-shutdown-threshold-pct")) {
		vty_out(vty, " %u",
			yang_dnode_get_uint8(dir, "./options/tw-shutdown-threshold-pct"));
		if (yang_dnode_exists(dir, "./options/tw-warning-only") &&
		    yang_dnode_get_bool(dir, "./options/tw-warning-only"))
			vty_out(vty, " warning-only");
	} else if (yang_dnode_exists(dir, "./options/tr-shutdown-threshold-pct")) {
		vty_out(vty, " %u restart %u",
			yang_dnode_get_uint8(dir, "./options/tr-shutdown-threshold-pct"),
			yang_dnode_get_uint16(dir, "./options/tr-restart-timer"));
	} else if (yang_dnode_exists(dir, "./options/shutdown-threshold-pct")) {
		vty_out(vty, " %u", yang_dnode_get_uint8(dir, "./options/shutdown-threshold-pct"));
	} else if (yang_dnode_exists(dir, "./options/restart-timer")) {
		vty_out(vty, " restart %u", yang_dnode_get_uint16(dir, "./options/restart-timer"));
	} else if (yang_dnode_exists(dir, "./options/warning-only") &&
		   yang_dnode_get_bool(dir, "./options/warning-only")) {
		vty_out(vty, " warning-only");
	}

	if (force)
		vty_out(vty, " force");

	vty_out(vty, "\n");
}

void bgp_nb_cli_show_peer_af_prefix_limit_noop(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults)
{
	/* Rendered with max-prefixes cli_show. */
}

static void bgp_nb_peer_af_addpath_apply(struct peer *peer, afi_t afi, safi_t safi,
					 const struct lyd_node *addpaths)
{
	const char *type = "none";
	uint16_t paths = 0;
	enum bgp_addpath_strat strat = BGP_ADDPATH_NONE;

	if (yang_dnode_exists(addpaths, "./path-type"))
		type = yang_dnode_get_string(addpaths, "./path-type");

	if (strmatch(type, "all"))
		strat = BGP_ADDPATH_ALL;
	else if (strmatch(type, "per-as"))
		strat = BGP_ADDPATH_BEST_PER_AS;
	else if (strmatch(type, "best-selected")) {
		strat = BGP_ADDPATH_BEST_SELECTED;
		if (yang_dnode_exists(addpaths, "./best-selected-paths"))
			paths = yang_dnode_get_uint8(addpaths, "./best-selected-paths");
	} else
		strat = BGP_ADDPATH_NONE;

	bgp_addpath_set_peer_type(peer, afi, safi, strat, paths);
}

int bgp_nb_peer_af_addpath_type_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	const struct lyd_node *addpaths;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	addpaths = yang_dnode_get_parent(args->dnode, "add-paths");
	if (!addpaths)
		return NB_ERR_NOT_FOUND;

	bgp_nb_peer_af_addpath_apply(peer, afi, safi, addpaths);
	return NB_OK;
}

int bgp_nb_peer_af_addpath_best_selected_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_addpath_type_modify(args);
}

int bgp_nb_peer_af_addpath_best_selected_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	const struct lyd_node *addpaths;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	addpaths = yang_dnode_get_parent(args->dnode, "add-paths");
	if (!addpaths)
		return NB_OK;

	bgp_nb_peer_af_addpath_apply(peer, afi, safi, addpaths);
	return NB_OK;
}

void bgp_nb_cli_show_peer_af_addpath_type(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults)
{
	const char *type = yang_dnode_get_string(dnode, NULL);
	const struct lyd_node *addpaths = yang_dnode_get_parent(dnode, "add-paths");

	if (strmatch(type, "all"))
		vty_out(vty, " neighbor %s addpath-tx-all-paths\n", bgp_nb_config_peer_name(dnode));
	else if (strmatch(type, "per-as"))
		vty_out(vty, " neighbor %s addpath-tx-bestpath-per-AS\n",
			bgp_nb_config_peer_name(dnode));
	else if (strmatch(type, "best-selected") && addpaths &&
		 yang_dnode_exists(addpaths, "./best-selected-paths"))
		vty_out(vty, " neighbor %s addpath-tx-best-selected %u\n",
			bgp_nb_config_peer_name(dnode),
			yang_dnode_get_uint8(addpaths, "./best-selected-paths"));
}

void bgp_nb_cli_show_peer_af_addpath_best_selected(struct vty *vty, const struct lyd_node *dnode,
						   bool show_defaults)
{
	/* Rendered with path-type cli_show. */
}

int bgp_nb_peer_af_disable_addpath_rx_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_flag_modify(args, PEER_FLAG_DISABLE_ADDPATH_RX);
}

void bgp_nb_cli_show_peer_af_disable_addpath_rx(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s disable-addpath-rx\n", bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_af_addpath_rx_limit_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	uint16_t limit;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	limit = yang_dnode_get_uint16(args->dnode, NULL);
	if (peer_af_flag_set(peer, afi, safi, PEER_FLAG_ADDPATH_RX_PATHS_LIMIT) < 0)
		return NB_ERR_RESOURCE;
	peer->addpath_paths_limit[afi][safi].send = limit;
	bgp_capability_send(peer->connection, afi, safi, CAPABILITY_CODE_PATHS_LIMIT,
			    CAPABILITY_ACTION_SET);
	return NB_OK;
}

int bgp_nb_peer_af_addpath_rx_limit_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	peer_af_flag_unset(peer, afi, safi, PEER_FLAG_ADDPATH_RX_PATHS_LIMIT);
	peer->addpath_paths_limit[afi][safi].send = 0;
	/*
	 * A tuple with zero Paths Limit is ignored by the receiver, so
	 * re-sending the capability alone would not clear the old limit.
	 * Withdraw the capability (clears all limits), and advertise it
	 * again with the limits still configured for other AFI/SAFIs.
	 */
	bgp_capability_send(peer->connection, afi, safi, CAPABILITY_CODE_PATHS_LIMIT,
			    CAPABILITY_ACTION_UNSET);
	bgp_capability_send(peer->connection, afi, safi, CAPABILITY_CODE_PATHS_LIMIT,
			    CAPABILITY_ACTION_SET);
	return NB_OK;
}

void bgp_nb_cli_show_peer_af_addpath_rx_limit(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults)
{
	vty_out(vty, " neighbor %s addpath-rx-paths-limit %u\n", bgp_nb_config_peer_name(dnode),
		yang_dnode_get_uint16(dnode, NULL));
}

static int bgp_nb_peer_af_advertise_map_apply(const struct lyd_node *cond)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	const char *aname, *cname;
	struct route_map *amap, *cmap;
	bool condition;

	peer = bgp_nb_config_peer(cond);
	if (!peer || !bgp_nb_dnode_afi_safi(cond, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	if (!yang_dnode_exists(cond, "./advertise-map"))
		return NB_OK;

	aname = yang_dnode_get_string(cond, "./advertise-map");
	if (yang_dnode_exists(cond, "./exist-map")) {
		cname = yang_dnode_get_string(cond, "./exist-map");
		condition = CONDITION_EXIST;
	} else if (yang_dnode_exists(cond, "./non-exist-map")) {
		cname = yang_dnode_get_string(cond, "./non-exist-map");
		condition = CONDITION_NON_EXIST;
	} else
		return NB_OK;

	amap = route_map_lookup_by_name(aname);
	cmap = route_map_lookup_by_name(cname);
	if (peer_advertise_map_set(peer, afi, safi, aname, amap, cname, cmap, condition) < 0)
		return NB_ERR_RESOURCE;
	return NB_OK;
}

static int bgp_nb_peer_af_advertise_map_clear(struct peer *peer, afi_t afi, safi_t safi)
{
	struct bgp_filter *filter = &peer->filter[afi][safi];

	if (!filter->advmap.aname)
		return NB_OK;

	if (peer_advertise_map_unset(peer, afi, safi, filter->advmap.aname, filter->advmap.amap,
				     filter->advmap.cname, filter->advmap.cmap,
				     filter->advmap.condition) < 0)
		return NB_ERR_RESOURCE;
	return NB_OK;
}

int bgp_nb_peer_af_advertise_map_modify(struct nb_cb_modify_args *args)
{
	const struct lyd_node *cond;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	cond = yang_dnode_get_parent(args->dnode, "conditional-advertisement");
	if (!cond)
		return NB_ERR_NOT_FOUND;
	return bgp_nb_peer_af_advertise_map_apply(cond);
}

int bgp_nb_peer_af_advertise_map_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	return bgp_nb_peer_af_advertise_map_clear(peer, afi, safi);
}

void bgp_nb_cli_show_peer_af_advertise_map(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	const struct lyd_node *cond = yang_dnode_get_parent(dnode, "conditional-advertisement");
	const char *cname;
	const char *kind;

	if (!cond)
		return;
	if (yang_dnode_exists(cond, "./exist-map")) {
		cname = yang_dnode_get_string(cond, "./exist-map");
		kind = "exist-map";
	} else if (yang_dnode_exists(cond, "./non-exist-map")) {
		cname = yang_dnode_get_string(cond, "./non-exist-map");
		kind = "non-exist-map";
	} else
		return;

	vty_out(vty, " neighbor %s advertise-map %s %s %s\n", bgp_nb_config_peer_name(dnode),
		yang_dnode_get_string(dnode, NULL), kind, cname);
}

void bgp_nb_cli_show_peer_af_advertise_map_cond(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults)
{
	/* Rendered with advertise-map cli_show. */
}


int bgp_nb_peer_af_advertise_cond_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_advertise_map_modify(args);
}

int bgp_nb_peer_af_advertise_cond_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Never re-apply on destroy: sibling leaf teardown must clear. */
	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;
	return bgp_nb_peer_af_advertise_map_clear(peer, afi, safi);
}

int bgp_nb_peer_af_accept_own_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_flag_modify(args, PEER_FLAG_ACCEPT_OWN);
}

void bgp_nb_cli_show_peer_af_accept_own(struct vty *vty, const struct lyd_node *dnode,
					bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s accept-own\n", bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_af_soo_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	struct ecommunity *ecomm_soo;
	const char *soo;

	if (args->event == NB_EV_VALIDATE) {
		soo = yang_dnode_get_string(args->dnode, NULL);
		ecomm_soo = ecommunity_str2com(soo, ECOMMUNITY_SITE_ORIGIN, 0);
		if (!ecomm_soo) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "Malformed SoO extended community");
			return NB_ERR_VALIDATION;
		}
		ecommunity_free(&ecomm_soo);
		return NB_OK;
	}

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	soo = yang_dnode_get_string(args->dnode, NULL);
	ecomm_soo = ecommunity_str2com(soo, ECOMMUNITY_SITE_ORIGIN, 0);
	if (!ecomm_soo)
		return NB_ERR_VALIDATION;
	ecommunity_str(ecomm_soo);

	/*
	 * peer_soo_set copies the value onto group members that are not
	 * overriding, and records the override on a member.
	 */
	if (peer_soo_set(peer, afi, safi, ecomm_soo) < 0) {
		ecommunity_free(&ecomm_soo);
		return NB_ERR_RESOURCE;
	}
	ecommunity_free(&ecomm_soo);
	return NB_OK;
}

int bgp_nb_peer_af_soo_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	/* Drop the override and inherit the peer-group value when bound. */
	peer_soo_unset(peer, afi, safi);
	return NB_OK;
}

void bgp_nb_cli_show_peer_af_soo(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, " neighbor %s soo %s\n", bgp_nb_config_peer_name(dnode),
		yang_dnode_get_string(dnode, NULL));
}

int bgp_nb_peer_af_upa_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_flag_modify(args, PEER_FLAG_UPA);
}

void bgp_nb_cli_show_peer_af_upa(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s upa\n", bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_af_nexthop_local_unchanged_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_flag_modify(args, PEER_FLAG_NEXTHOP_LOCAL_UNCHANGED);
}

void bgp_nb_cli_show_peer_af_nexthop_local_unchanged(struct vty *vty, const struct lyd_node *dnode,
						     bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s nexthop-local unchanged\n",
			bgp_nb_config_peer_name(dnode));
}


static int bgp_nb_peer_af_orf_apply(struct peer *peer, afi_t afi, safi_t safi, bool send,
				    bool recv, bool set)
{
	int ret = 0;

	if (send) {
		if (set)
			ret |= peer_af_flag_set(peer, afi, safi, PEER_FLAG_ORF_PREFIX_SM);
		else
			ret |= peer_af_flag_unset(peer, afi, safi, PEER_FLAG_ORF_PREFIX_SM);
	}
	if (recv) {
		if (set)
			ret |= peer_af_flag_set(peer, afi, safi, PEER_FLAG_ORF_PREFIX_RM);
		else
			ret |= peer_af_flag_unset(peer, afi, safi, PEER_FLAG_ORF_PREFIX_RM);
	}

	bgp_capability_send(peer->connection, afi, safi, CAPABILITY_CODE_ORF,
			    set ? CAPABILITY_ACTION_SET : CAPABILITY_ACTION_UNSET);
	return ret < 0 ? NB_ERR_RESOURCE : NB_OK;
}

int bgp_nb_peer_af_orf_send_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL)) {
		peer_af_flag_unset(peer, afi, safi, PEER_FLAG_ORF_PREFIX_RM);
		return bgp_nb_peer_af_orf_apply(peer, afi, safi, true, false, true);
	}
	return bgp_nb_peer_af_orf_apply(peer, afi, safi, true, false, false);
}

int bgp_nb_peer_af_orf_send_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	return bgp_nb_peer_af_orf_apply(peer, afi, safi, true, false, false);
}

void bgp_nb_cli_show_peer_af_orf_send(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s capability orf prefix-list send\n",
			bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_af_orf_receive_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL)) {
		peer_af_flag_unset(peer, afi, safi, PEER_FLAG_ORF_PREFIX_SM);
		return bgp_nb_peer_af_orf_apply(peer, afi, safi, false, true, true);
	}
	return bgp_nb_peer_af_orf_apply(peer, afi, safi, false, true, false);
}

int bgp_nb_peer_af_orf_receive_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	return bgp_nb_peer_af_orf_apply(peer, afi, safi, false, true, false);
}

void bgp_nb_cli_show_peer_af_orf_receive(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s capability orf prefix-list receive\n",
			bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_af_orf_both_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	return bgp_nb_peer_af_orf_apply(peer, afi, safi, true, true,
					yang_dnode_get_bool(args->dnode, NULL));
}

int bgp_nb_peer_af_orf_both_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	return bgp_nb_peer_af_orf_apply(peer, afi, safi, true, true, false);
}

void bgp_nb_cli_show_peer_af_orf_both(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s capability orf prefix-list both\n",
			bgp_nb_config_peer_name(dnode));
}

static bool bgp_nb_path_attr_forbidden(const struct lyd_node *dnode, uint8_t attr_num,
				       bool withdraw, char *errmsg, size_t errmsg_len)
{
	bool ebgp;

	/*
	 * Peer-independent attributes are rejected even when the neighbor
	 * is created in this same candidate and has no running peer yet.
	 */
	ebgp = bgp_nb_candidate_peer_sort(dnode) == BGP_PEER_EBGP;
	return bgp_path_attribute_discard_forbidden(attr_num, ebgp, withdraw, errmsg, errmsg_len);
}

static void bgp_nb_peer_path_attr_soft_clear(struct peer *peer)
{
	afi_t afi;
	safi_t safi;

	FOREACH_AFI_SAFI (afi, safi)
		peer_clear_soft(peer, afi, safi, BGP_CLEAR_SOFT_IN);
}

/*
 * libyang sibling lists are circular: the first node's prev is the last
 * node, and yang_is_last_list_dnode() is true only for a one-element list.
 * Print once, from the first leaf-list entry of this name.
 */
static bool bgp_nb_leaflist_is_first(const struct lyd_node *dnode)
{
	const struct lyd_node *sib;

	if (!dnode)
		return false;

	sib = dnode->prev;
	while (sib && sib->next) {
		if (sib->schema && strmatch(sib->schema->name, dnode->schema->name))
			return false;
		if (!sib->prev || sib->prev == sib || sib->prev->next == NULL)
			break;
		sib = sib->prev;
	}
	return true;
}

static void bgp_nb_cli_show_peer_path_attr_list(struct vty *vty, const struct lyd_node *dnode,
						const char *leaf_name, const char *cli_kw)
{
	const struct lyd_node *parent, *child;

	if (!bgp_nb_leaflist_is_first(dnode))
		return;

	parent = lyd_parent(dnode);
	vty_out(vty, " neighbor %s path-attribute %s", bgp_nb_config_peer_name(dnode), cli_kw);
	for (child = lyd_child(parent); child; child = child->next) {
		if (child->schema->nodetype != LYS_LEAFLIST)
			continue;
		if (!strmatch(child->schema->name, leaf_name))
			continue;
		vty_out(vty, " %u", yang_dnode_get_uint8(child, NULL));
	}
	vty_out(vty, "\n");
}

int bgp_nb_peer_path_attr_discard_create(struct nb_cb_create_args *args)
{
	struct peer *peer;
	uint8_t attr_num;

	switch (args->event) {
	case NB_EV_VALIDATE:
		attr_num = yang_dnode_get_uint8(args->dnode, NULL);
		if (bgp_nb_path_attr_forbidden(args->dnode, attr_num, false, args->errmsg,
					       args->errmsg_len))
			return NB_ERR_VALIDATION;
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	attr_num = yang_dnode_get_uint8(args->dnode, NULL);
	peer->discard_attrs[attr_num] = true;
	bgp_nb_peer_path_attr_soft_clear(peer);
	return NB_OK;
}

int bgp_nb_peer_path_attr_discard_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	uint8_t attr_num;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_OK;

	attr_num = yang_dnode_get_uint8(args->dnode, NULL);
	peer->discard_attrs[attr_num] = false;
	bgp_nb_peer_path_attr_soft_clear(peer);
	return NB_OK;
}

void bgp_nb_cli_show_peer_path_attr_discard(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults)
{
	bgp_nb_cli_show_peer_path_attr_list(vty, dnode, "discard", "discard");
}

int bgp_nb_peer_path_attr_withdraw_create(struct nb_cb_create_args *args)
{
	struct peer *peer;
	uint8_t attr_num;

	switch (args->event) {
	case NB_EV_VALIDATE:
		attr_num = yang_dnode_get_uint8(args->dnode, NULL);
		if (bgp_nb_path_attr_forbidden(args->dnode, attr_num, true, args->errmsg,
					       args->errmsg_len))
			return NB_ERR_VALIDATION;
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	attr_num = yang_dnode_get_uint8(args->dnode, NULL);
	peer->withdraw_attrs[attr_num] = true;
	bgp_nb_peer_path_attr_soft_clear(peer);
	return NB_OK;
}

int bgp_nb_peer_path_attr_withdraw_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	uint8_t attr_num;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_OK;

	attr_num = yang_dnode_get_uint8(args->dnode, NULL);
	peer->withdraw_attrs[attr_num] = false;
	bgp_nb_peer_path_attr_soft_clear(peer);
	return NB_OK;
}

void bgp_nb_cli_show_peer_path_attr_withdraw(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults)
{
	bgp_nb_cli_show_peer_path_attr_list(vty, dnode, "treat-as-withdraw", "treat-as-withdraw");
}

static int bgp_nb_peer_gr_cmd(struct peer *peer, enum peer_gr_command cmd)
{
	int result;
	int ret = BGP_GR_SUCCESS;

	result = bgp_neighbor_graceful_restart(peer, cmd);
	if (result == BGP_GR_SUCCESS)
		VTY_BGP_GR_ROUTER_DETECT_AND_SEND_CAPABILITY_TO_ZEBRA(peer->bgp, peer->bgp->peer,
								      ret);

	if (result == BGP_GR_FAILURE || ret == BGP_ERR_INVALID_VALUE)
		return NB_ERR_RESOURCE;
	return NB_OK;
}

int bgp_nb_peer_gr_enable_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL))
		return bgp_nb_peer_gr_cmd(peer, PEER_GR_CMD);
	return bgp_nb_peer_gr_cmd(peer, NO_PEER_GR_CMD);
}

int bgp_nb_peer_gr_enable_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_OK;

	return bgp_nb_peer_gr_cmd(peer, NO_PEER_GR_CMD);
}

void bgp_nb_cli_show_peer_gr_enable(struct vty *vty, const struct lyd_node *dnode,
				    bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s graceful-restart\n", bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_gr_helper_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL))
		return bgp_nb_peer_gr_cmd(peer, PEER_HELPER_CMD);
	return bgp_nb_peer_gr_cmd(peer, NO_PEER_HELPER_CMD);
}

int bgp_nb_peer_gr_helper_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_OK;

	return bgp_nb_peer_gr_cmd(peer, NO_PEER_HELPER_CMD);
}

void bgp_nb_cli_show_peer_gr_helper(struct vty *vty, const struct lyd_node *dnode,
				    bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s graceful-restart-helper\n",
			bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_gr_disable_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL))
		return bgp_nb_peer_gr_cmd(peer, PEER_DISABLE_CMD);
	return bgp_nb_peer_gr_cmd(peer, NO_PEER_DISABLE_CMD);
}

int bgp_nb_peer_gr_disable_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_OK;

	return bgp_nb_peer_gr_cmd(peer, NO_PEER_DISABLE_CMD);
}

void bgp_nb_cli_show_peer_gr_disable(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s graceful-restart-disable\n",
			bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_aigp_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_set(peer, PEER_FLAG_AIGP);
	else
		peer_flag_unset(peer, PEER_FLAG_AIGP);
	return NB_OK;
}

void bgp_nb_cli_show_peer_aigp(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s aigp\n", bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, " no neighbor %s aigp\n", bgp_nb_config_peer_name(dnode));
}

static int bgp_nb_peer_bool_flag_modify(struct nb_cb_modify_args *args, uint64_t flag)
{
	struct peer *peer;
	int ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL))
		ret = peer_flag_set(peer, flag);
	else
		ret = peer_flag_unset(peer, flag);

	if (ret < 0)
		return NB_ERR_RESOURCE;
	return NB_OK;
}

static void bgp_nb_cli_show_peer_bool_flag(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults, const char *cmd)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s %s\n", bgp_nb_config_peer_name(dnode), cmd);
	else if (show_defaults)
		vty_out(vty, " no neighbor %s %s\n", bgp_nb_config_peer_name(dnode), cmd);
}

int bgp_nb_peer_extended_link_bw_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_bool_flag_modify(args, PEER_FLAG_EXTENDED_LINK_BANDWIDTH);
}

void bgp_nb_cli_show_peer_extended_link_bw(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	bgp_nb_cli_show_peer_bool_flag(vty, dnode, show_defaults, "extended-link-bandwidth");
}

int bgp_nb_peer_disable_link_bw_ieee_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_bool_flag_modify(args, PEER_FLAG_DISABLE_LINK_BW_ENCODING_IEEE);
}

void bgp_nb_cli_show_peer_disable_link_bw_ieee(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults)
{
	bgp_nb_cli_show_peer_bool_flag(vty, dnode, show_defaults, "disable-link-bw-encoding-ieee");
}

int bgp_nb_peer_extended_opt_params_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_bool_flag_modify(args, PEER_FLAG_EXTENDED_OPT_PARAMS);
}

void bgp_nb_cli_show_peer_extended_opt_params(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults)
{
	bgp_nb_cli_show_peer_bool_flag(vty, dnode, show_defaults, "extended-optional-parameters");
}

int bgp_nb_peer_send_nhc_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_bool_flag_modify(args, PEER_FLAG_SEND_NHC_ATTRIBUTE);
}

void bgp_nb_cli_show_peer_send_nhc(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults)
{
	bgp_nb_cli_show_peer_bool_flag(vty, dnode, show_defaults, "send-nexthop-characteristics");
}

int bgp_nb_peer_as_loop_detection_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_bool_flag_modify(args, PEER_FLAG_AS_LOOP_DETECTION);
}

void bgp_nb_cli_show_peer_as_loop_detection(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults)
{
	bgp_nb_cli_show_peer_bool_flag(vty, dnode, show_defaults, "sender-as-path-loop-detection");
}

int bgp_nb_peer_oad_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL)) {
		if (peer->sort == BGP_PEER_EBGP)
			peer->sub_sort = BGP_PEER_EBGP_OAD;
	} else
		peer->sub_sort = 0;
	return NB_OK;
}

void bgp_nb_cli_show_peer_oad(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s oad\n", bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, " no neighbor %s oad\n", bgp_nb_config_peer_name(dnode));
}

static void bgp_nb_peer_announce_routes(struct peer *peer)
{
	afi_t afi;
	safi_t safi;
	struct peer_af *paf;

	FOREACH_AFI_SAFI (afi, safi) {
		if (!peer->afc[afi][safi])
			continue;
		paf = peer_af_find(peer, afi, safi);
		if (paf) {
			update_group_adjust_peer(paf);
			bgp_announce_route(peer, afi, safi, false);
		}
	}
}

static void bgp_nb_peer_gs_soft_reset(struct peer *peer)
{
	struct listnode *node, *nnode;
	struct peer *member;
	afi_t afi;
	safi_t safi;

	/*
	 * Match classic neighbor graceful-shutdown: soft-in clear plus
	 * re-announce so originated routes pick up/drop GSHUT / loc-pref 0.
	 */
	if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
			FOREACH_AFI_SAFI (afi, safi)
				peer_clear_soft(member, afi, safi, BGP_CLEAR_SOFT_IN);
			bgp_nb_peer_announce_routes(member);
		}
	} else {
		FOREACH_AFI_SAFI (afi, safi)
			peer_clear_soft(peer, afi, safi, BGP_CLEAR_SOFT_IN);
		bgp_nb_peer_announce_routes(peer);
	}
}

int bgp_nb_peer_graceful_shutdown_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	int ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL))
		ret = peer_flag_set(peer, PEER_FLAG_GRACEFUL_SHUTDOWN);
	else
		ret = peer_flag_unset(peer, PEER_FLAG_GRACEFUL_SHUTDOWN);

	if (ret == 0)
		bgp_nb_peer_gs_soft_reset(peer);
	else if (ret < 0)
		return NB_ERR_RESOURCE;
	return NB_OK;
}

void bgp_nb_cli_show_peer_graceful_shutdown(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s graceful-shutdown\n", bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, " no neighbor %s graceful-shutdown\n", bgp_nb_config_peer_name(dnode));
}

/*
 * flowspec local-install
 */
static bool bgp_nb_fs_local_install_heads(struct bgp *bgp, afi_t afi,
					  struct bgp_pbr_interface_head **head, bool **any)
{
	if (!bgp->bgp_pbr_cfg || (afi != AFI_IP && afi != AFI_IP6))
		return false;

	if (afi == AFI_IP) {
		*head = &bgp->bgp_pbr_cfg->ifaces_by_name_ipv4;
		*any = &bgp->bgp_pbr_cfg->pbr_interface_any_ipv4;
	} else {
		*head = &bgp->bgp_pbr_cfg->ifaces_by_name_ipv6;
		*any = &bgp->bgp_pbr_cfg->pbr_interface_any_ipv6;
	}
	return true;
}

static int bgp_nb_fs_apply_enable(struct bgp *bgp, afi_t afi, bool enable, bool has_interfaces)
{
	struct bgp_pbr_interface_head *head;
	bool *any;

	if (!bgp_nb_fs_local_install_heads(bgp, afi, &head, &any))
		return NB_OK;

	if (!enable) {
		bgp_pbr_reset(bgp, afi);
		*any = false;
		return NB_OK;
	}

	if (!has_interfaces) {
		bgp_pbr_reset(bgp, afi);
		*any = true;
	} else
		*any = false;

	return NB_OK;
}

int bgp_nb_fs_local_install_enable_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	const struct lyd_node *li;
	bool enable;
	bool has_interfaces;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	li = yang_dnode_get_parent(args->dnode, "local-install");
	has_interfaces = li && yang_dnode_exists(li, "./interface");
	enable = yang_dnode_get_bool(args->dnode, NULL);

	return bgp_nb_fs_apply_enable(bgp, afi, enable, has_interfaces);
}

int bgp_nb_fs_local_install_enable_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	const struct lyd_node *li;
	bool has_interfaces;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	/* Destroy restores YANG default enable=true. */
	li = yang_dnode_get_parent(args->dnode, "local-install");
	has_interfaces = li && yang_dnode_exists(li, "./interface");

	return bgp_nb_fs_apply_enable(bgp, afi, true, has_interfaces);
}

int bgp_nb_fs_local_install_interface_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	struct bgp_pbr_interface_head *head;
	bool *any;
	struct bgp_pbr_interface *pbr_if;
	const char *ifname;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;
	if (!bgp_nb_fs_local_install_heads(bgp, afi, &head, &any))
		return NB_OK;

	ifname = yang_dnode_get_string(args->dnode, NULL);
	pbr_if = bgp_pbr_interface_lookup(ifname, head);
	if (pbr_if)
		return NB_OK;

	pbr_if = XCALLOC(MTYPE_TMP, sizeof(struct bgp_pbr_interface));
	strlcpy(pbr_if->name, ifname, IFNAMSIZ);
	RB_INSERT(bgp_pbr_interface_head, head, pbr_if);
	*any = false;
	return NB_OK;
}

int bgp_nb_fs_local_install_interface_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	struct bgp_pbr_interface_head *head;
	bool *any;
	struct bgp_pbr_interface *pbr_if;
	const char *ifname;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;
	if (!bgp_nb_fs_local_install_heads(bgp, afi, &head, &any))
		return NB_OK;

	ifname = yang_dnode_get_string(args->dnode, NULL);
	pbr_if = bgp_pbr_interface_lookup(ifname, head);
	if (!pbr_if)
		return NB_OK;

	RB_REMOVE(bgp_pbr_interface_head, head, pbr_if);
	XFREE(MTYPE_TMP, pbr_if);

	if (RB_EMPTY(bgp_pbr_interface_head, head))
		*any = true;

	return NB_OK;
}

void bgp_nb_cli_show_fs_local_install_interface(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults)
{
	vty_out(vty, "  local-install %s\n", yang_dnode_get_string(dnode, NULL));
}

/*
 * neighbor LS local/remote-link-id
 */
int bgp_nb_peer_ls_local_link_id_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	struct bgp *bgp;
	uint32_t link_id;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	bgp = peer->bgp;
	link_id = yang_dnode_get_uint32(args->dnode, NULL);

	if (CHECK_FLAG(peer->flags, PEER_FLAG_LS_LOCAL_LINK_ID) &&
	    peer->ls_local_link_id == link_id)
		return NB_OK;

	if (bgp->ls_info && bgp->ls_info->enable_distribution)
		bgp_ls_withdraw_bgp_link(bgp, peer);

	peer->ls_local_link_id = link_id;
	SET_FLAG(peer->flags, PEER_FLAG_LS_LOCAL_LINK_ID);

	if (bgp->ls_info && bgp->ls_info->enable_distribution)
		bgp_ls_originate_bgp_link(bgp, peer);

	return NB_OK;
}

int bgp_nb_peer_ls_local_link_id_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_OK;

	if (!CHECK_FLAG(peer->flags, PEER_FLAG_LS_LOCAL_LINK_ID))
		return NB_OK;

	bgp = peer->bgp;
	if (bgp->ls_info && bgp->ls_info->enable_distribution)
		bgp_ls_withdraw_bgp_link(bgp, peer);

	peer->ls_local_link_id = 0;
	UNSET_FLAG(peer->flags, PEER_FLAG_LS_LOCAL_LINK_ID);

	if (bgp->ls_info && bgp->ls_info->enable_distribution)
		bgp_ls_originate_bgp_link(bgp, peer);

	return NB_OK;
}

void bgp_nb_cli_show_peer_ls_local_link_id(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	vty_out(vty, " neighbor %s local-link-id %u\n", bgp_nb_config_peer_name(dnode),
		yang_dnode_get_uint32(dnode, NULL));
}

int bgp_nb_peer_ls_remote_link_id_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	struct bgp *bgp;
	uint32_t link_id;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	bgp = peer->bgp;
	link_id = yang_dnode_get_uint32(args->dnode, NULL);

	if (CHECK_FLAG(peer->flags, PEER_FLAG_LS_REMOTE_LINK_ID) &&
	    peer->ls_remote_link_id == link_id)
		return NB_OK;

	if (bgp->ls_info && bgp->ls_info->enable_distribution)
		bgp_ls_withdraw_bgp_link(bgp, peer);

	peer->ls_remote_link_id = link_id;
	SET_FLAG(peer->flags, PEER_FLAG_LS_REMOTE_LINK_ID);

	if (bgp->ls_info && bgp->ls_info->enable_distribution)
		bgp_ls_originate_bgp_link(bgp, peer);

	return NB_OK;
}

int bgp_nb_peer_ls_remote_link_id_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_OK;

	if (!CHECK_FLAG(peer->flags, PEER_FLAG_LS_REMOTE_LINK_ID))
		return NB_OK;

	bgp = peer->bgp;
	if (bgp->ls_info && bgp->ls_info->enable_distribution)
		bgp_ls_withdraw_bgp_link(bgp, peer);

	peer->ls_remote_link_id = 0;
	UNSET_FLAG(peer->flags, PEER_FLAG_LS_REMOTE_LINK_ID);

	if (bgp->ls_info && bgp->ls_info->enable_distribution)
		bgp_ls_originate_bgp_link(bgp, peer);

	return NB_OK;
}

void bgp_nb_cli_show_peer_ls_remote_link_id(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults)
{
	vty_out(vty, " neighbor %s remote-link-id %u\n", bgp_nb_config_peer_name(dnode),
		yang_dnode_get_uint32(dnode, NULL));
}

/*
 * BMP — global/bmp-config
 *
 * Configuration legality belongs in NB_EV_VALIDATE (and YANG must/when),
 * using the candidate dnode tree only.  APPLY dispatches through bmp_nb_cb
 * (filled by bgpd_bmp.so); core never calls bmp_* module symbols.
 */
struct bmp_nb_ops *bmp_nb_cb;

int bgp_nb_bmp_mirror_buffer_limit_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
		/* Range enforced by YANG (0..4294967294). */
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	if (!bmp_nb_cb || !bmp_nb_cb->mirror_buffer_limit_set)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp)
		return NB_ERR_NOT_FOUND;

	return bmp_nb_cb->mirror_buffer_limit_set(bgp, yang_dnode_get_uint32(args->dnode, NULL));
}

int bgp_nb_bmp_mirror_buffer_limit_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	if (!bmp_nb_cb || !bmp_nb_cb->mirror_buffer_limit_unset)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp)
		return NB_OK;

	return bmp_nb_cb->mirror_buffer_limit_unset(bgp);
}

void bgp_nb_cli_show_bmp_mirror_buffer_limit(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults)
{
	vty_out(vty, " !\n bmp mirror buffer-limit %u\n", yang_dnode_get_uint32(dnode, NULL));
}

int bgp_nb_bmp_target_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	const char *name;
	void *bt;

	switch (args->event) {
	case NB_EV_VALIDATE:
		/*
		 * Target identity is the YANG list key.  Cross-leaf constraints
		 * for children (retry bounds, self-import, …) live on those
		 * nodes / YANG must statements — not via operational BMP.
		 */
		name = yang_dnode_get_string(args->dnode, "./target-name");
		if (!name || !name[0]) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "BMP target name must not be empty");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	if (!bmp_nb_cb || !bmp_nb_cb->target_get)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp)
		return NB_ERR_NOT_FOUND;

	name = yang_dnode_get_string(args->dnode, "./target-name");
	bt = bmp_nb_cb->target_get(bgp, name);
	if (!bt)
		return NB_ERR_RESOURCE;

	nb_running_set_entry(args->dnode, bt);
	return NB_OK;
}

int bgp_nb_bmp_target_destroy(struct nb_cb_destroy_args *args)
{
	void *bt;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bt = nb_running_unset_entry(args->dnode);
	if (bt && bmp_nb_cb && bmp_nb_cb->target_put)
		bmp_nb_cb->target_put(bt);
	return NB_OK;
}

void bgp_nb_cli_show_bmp_target(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, " !\n bmp targets %s\n", yang_dnode_get_string(dnode, "./target-name"));
}

void bgp_nb_cli_show_bmp_target_end(struct vty *vty, const struct lyd_node *dnode)
{
	vty_out(vty, " exit\n");
}

int bgp_nb_bmp_target_mirror_modify(struct nb_cb_modify_args *args)
{
	void *bt;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	if (!bmp_nb_cb || !bmp_nb_cb->target_mirror_set)
		return NB_OK;

	bt = nb_running_get_entry(args->dnode, NULL, true);
	if (!bt)
		return NB_ERR_NOT_FOUND;

	bmp_nb_cb->target_mirror_set(bt, yang_dnode_get_bool(args->dnode, NULL));
	return NB_OK;
}

void bgp_nb_cli_show_bmp_target_mirror(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "  bmp mirror\n");
}

int bgp_nb_bmp_target_stats_time_modify(struct nb_cb_modify_args *args)
{
	void *bt;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	if (!bmp_nb_cb || !bmp_nb_cb->target_stats_set)
		return NB_OK;

	bt = nb_running_get_entry(args->dnode, NULL, true);
	if (!bt)
		return NB_ERR_NOT_FOUND;

	bmp_nb_cb->target_stats_set(bt, yang_dnode_get_uint32(args->dnode, NULL));
	return NB_OK;
}

int bgp_nb_bmp_target_stats_time_destroy(struct nb_cb_destroy_args *args)
{
	void *bt;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	if (!bmp_nb_cb || !bmp_nb_cb->target_stats_set)
		return NB_OK;

	bt = nb_running_get_entry(args->dnode, NULL, true);
	if (!bt)
		return NB_OK;

	bmp_nb_cb->target_stats_set(bt, 0);
	return NB_OK;
}

void bgp_nb_cli_show_bmp_target_stats_time(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	vty_out(vty, "  bmp stats interval %u\n", yang_dnode_get_uint32(dnode, NULL));
}

int bgp_nb_bmp_target_stats_experimental_modify(struct nb_cb_modify_args *args)
{
	void *bt;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	if (!bmp_nb_cb || !bmp_nb_cb->target_stats_experimental_set)
		return NB_OK;

	bt = nb_running_get_entry(args->dnode, NULL, true);
	if (!bt)
		return NB_ERR_NOT_FOUND;

	bmp_nb_cb->target_stats_experimental_set(bt, yang_dnode_get_bool(args->dnode, NULL));
	return NB_OK;
}

void bgp_nb_cli_show_bmp_target_stats_experimental(struct vty *vty, const struct lyd_node *dnode,
						   bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "  no bmp stats send-experimental\n");
	else if (show_defaults)
		vty_out(vty, "  bmp stats send-experimental\n");
}

static bool bgp_nb_bmp_acl_is_v6(const struct lyd_node *dnode)
{
	return strmatch(dnode->schema->name, "ipv6-access-list");
}

int bgp_nb_bmp_target_acl_modify(struct nb_cb_modify_args *args)
{
	void *bt;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	if (!bmp_nb_cb || !bmp_nb_cb->target_acl_set)
		return NB_OK;

	bt = nb_running_get_entry(args->dnode, NULL, true);
	if (!bt)
		return NB_ERR_NOT_FOUND;

	bmp_nb_cb->target_acl_set(bt, bgp_nb_bmp_acl_is_v6(args->dnode),
				  yang_dnode_get_string(args->dnode, NULL));
	return NB_OK;
}

int bgp_nb_bmp_target_acl_destroy(struct nb_cb_destroy_args *args)
{
	void *bt;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	if (!bmp_nb_cb || !bmp_nb_cb->target_acl_set)
		return NB_OK;

	bt = nb_running_get_entry(args->dnode, NULL, true);
	if (!bt)
		return NB_OK;

	bmp_nb_cb->target_acl_set(bt, bgp_nb_bmp_acl_is_v6(args->dnode), NULL);
	return NB_OK;
}

void bgp_nb_cli_show_bmp_target_acl_v4(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults)
{
	vty_out(vty, "  ip access-list %s\n", yang_dnode_get_string(dnode, NULL));
}

void bgp_nb_cli_show_bmp_target_acl_v6(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults)
{
	vty_out(vty, "  ipv6 access-list %s\n", yang_dnode_get_string(dnode, NULL));
}

static bool bgp_nb_bmp_initiation_is_sysdescr(const struct lyd_node *dnode)
{
	return strmatch(dnode->schema->name, "initiation-sysdescr");
}

int bgp_nb_bmp_target_initiation_modify(struct nb_cb_modify_args *args)
{
	void *bt;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	if (!bmp_nb_cb || !bmp_nb_cb->target_initiation_set)
		return NB_OK;

	bt = nb_running_get_entry(args->dnode, NULL, true);
	if (!bt)
		return NB_ERR_NOT_FOUND;

	bmp_nb_cb->target_initiation_set(bt, bgp_nb_bmp_initiation_is_sysdescr(args->dnode),
					 yang_dnode_get_string(args->dnode, NULL));
	return NB_OK;
}

int bgp_nb_bmp_target_initiation_destroy(struct nb_cb_destroy_args *args)
{
	void *bt;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	if (!bmp_nb_cb || !bmp_nb_cb->target_initiation_set)
		return NB_OK;

	bt = nb_running_get_entry(args->dnode, NULL, true);
	if (!bt)
		return NB_OK;

	bmp_nb_cb->target_initiation_set(bt, bgp_nb_bmp_initiation_is_sysdescr(args->dnode), NULL);
	return NB_OK;
}

void bgp_nb_cli_show_bmp_target_initiation_sysdescr(struct vty *vty, const struct lyd_node *dnode,
						    bool show_defaults)
{
	vty_out(vty, "  bmp initiation sysDescr %s\n", yang_dnode_get_string(dnode, NULL));
}

void bgp_nb_cli_show_bmp_target_initiation_sysname(struct vty *vty, const struct lyd_node *dnode,
						   bool show_defaults)
{
	vty_out(vty, "  bmp initiation sysName %s\n", yang_dnode_get_string(dnode, NULL));
}

static int bgp_nb_bmp_port_check(uint32_t port, char *errmsg, size_t errmsg_len)
{
	if (port < 1 || port > 65535) {
		snprintfrr(errmsg, errmsg_len, "BMP tcp-port %" PRIu32 " is outside 1..65535", port);
		return NB_ERR_VALIDATION;
	}
	return NB_OK;
}

int bgp_nb_bmp_listener_create(struct nb_cb_create_args *args)
{
	union sockunion su;
	const char *addr;
	uint32_t port32;
	uint16_t port;
	void *bt;

	addr = yang_dnode_get_string(args->dnode, "./address");
	port32 = yang_dnode_get_uint32(args->dnode, "./tcp-port");
	port = port32;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (bgp_nb_bmp_port_check(port32, args->errmsg, args->errmsg_len) != NB_OK)
			return NB_ERR_VALIDATION;
		if (str2sockunion(addr, &su) < 0) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "Malformed BMP listener address");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	if (!bmp_nb_cb || !bmp_nb_cb->listener_set)
		return NB_OK;

	bt = nb_running_get_entry(args->dnode, NULL, true);
	if (!bt)
		return NB_ERR_NOT_FOUND;

	return bmp_nb_cb->listener_set(bt, addr, port);
}

int bgp_nb_bmp_listener_destroy(struct nb_cb_destroy_args *args)
{
	union sockunion su;
	const char *addr;
	uint32_t port32;
	uint16_t port;
	void *bt;

	addr = yang_dnode_get_string(args->dnode, "./address");
	port32 = yang_dnode_get_uint32(args->dnode, "./tcp-port");
	port = port32;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (bgp_nb_bmp_port_check(port32, args->errmsg, args->errmsg_len) != NB_OK)
			return NB_ERR_VALIDATION;
		if (str2sockunion(addr, &su) < 0) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "Malformed BMP listener address");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	if (!bmp_nb_cb || !bmp_nb_cb->listener_unset)
		return NB_OK;

	bt = nb_running_get_entry(args->dnode, NULL, true);
	if (!bt)
		return NB_OK;

	return bmp_nb_cb->listener_unset(bt, addr, port);
}

void bgp_nb_cli_show_bmp_listener(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, "   bmp listener %s port %u\n", yang_dnode_get_string(dnode, "./address"),
		yang_dnode_get_uint32(dnode, "./tcp-port"));
}

/* YANG defaults for outbound session retry (frr-bgp-bmp.yang). */
#define BGP_NB_BMP_DFLT_MINRETRY 30000U
#define BGP_NB_BMP_DFLT_MAXRETRY 720000U

static int bgp_nb_bmp_connect_validate(const struct lyd_node *dnode, char *errmsg,
				       size_t errmsg_len)
{
	uint32_t minretry = BGP_NB_BMP_DFLT_MINRETRY;
	uint32_t maxretry = BGP_NB_BMP_DFLT_MAXRETRY;
	uint32_t port = yang_dnode_get_uint32(dnode, "./tcp-port");

	if (bgp_nb_bmp_port_check(port, errmsg, errmsg_len) != NB_OK)
		return NB_ERR_VALIDATION;

	if (yang_dnode_exists(dnode, "./min-retry-time"))
		minretry = yang_dnode_get_uint32(dnode, "./min-retry-time");
	if (yang_dnode_exists(dnode, "./max-retry-time"))
		maxretry = yang_dnode_get_uint32(dnode, "./max-retry-time");
	if (maxretry < minretry) {
		snprintfrr(errmsg, errmsg_len, "BMP max-retry-time must be >= min-retry-time");
		return NB_ERR_VALIDATION;
	}
	return NB_OK;
}

static int bgp_nb_bmp_connect_apply(const struct lyd_node *dnode)
{
	const char *hostname;
	const char *srcif = NULL;
	uint16_t port;
	uint32_t minretry = BGP_NB_BMP_DFLT_MINRETRY;
	uint32_t maxretry = BGP_NB_BMP_DFLT_MAXRETRY;
	void *bt;

	if (!bmp_nb_cb || !bmp_nb_cb->connect_set)
		return NB_OK;

	bt = nb_running_get_entry(dnode, NULL, true);
	if (!bt)
		return NB_ERR_NOT_FOUND;

	hostname = yang_dnode_get_string(dnode, "./hostname");
	port = yang_dnode_get_uint32(dnode, "./tcp-port");
	if (yang_dnode_exists(dnode, "./min-retry-time"))
		minretry = yang_dnode_get_uint32(dnode, "./min-retry-time");
	if (yang_dnode_exists(dnode, "./max-retry-time"))
		maxretry = yang_dnode_get_uint32(dnode, "./max-retry-time");
	if (yang_dnode_exists(dnode, "./source-interface"))
		srcif = yang_dnode_get_string(dnode, "./source-interface");

	return bmp_nb_cb->connect_set(bt, hostname, port, minretry, maxretry, srcif);
}

int bgp_nb_bmp_connect_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_nb_bmp_connect_validate(args->dnode, args->errmsg, args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	return bgp_nb_bmp_connect_apply(args->dnode);
}

int bgp_nb_bmp_connect_destroy(struct nb_cb_destroy_args *args)
{
	const char *hostname;
	const char *srcif = NULL;
	uint16_t port;
	void *bt;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	if (!bmp_nb_cb || !bmp_nb_cb->connect_unset)
		return NB_OK;

	bt = nb_running_get_entry(args->dnode, NULL, true);
	if (!bt)
		return NB_OK;

	hostname = yang_dnode_get_string(args->dnode, "./hostname");
	port = yang_dnode_get_uint32(args->dnode, "./tcp-port");
	if (yang_dnode_exists(args->dnode, "./source-interface"))
		srcif = yang_dnode_get_string(args->dnode, "./source-interface");

	return bmp_nb_cb->connect_unset(bt, hostname, port, srcif);
}

void bgp_nb_cli_show_bmp_connect(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	uint32_t minretry = BGP_NB_BMP_DFLT_MINRETRY;
	uint32_t maxretry = BGP_NB_BMP_DFLT_MAXRETRY;

	if (yang_dnode_exists(dnode, "./min-retry-time"))
		minretry = yang_dnode_get_uint32(dnode, "./min-retry-time");
	if (yang_dnode_exists(dnode, "./max-retry-time"))
		maxretry = yang_dnode_get_uint32(dnode, "./max-retry-time");

	vty_out(vty, "  bmp connect %s port %u min-retry %u max-retry %u",
		yang_dnode_get_string(dnode, "./hostname"),
		yang_dnode_get_uint32(dnode, "./tcp-port"), minretry, maxretry);
	if (yang_dnode_exists(dnode, "./source-interface"))
		vty_out(vty, " source-interface %s",
			yang_dnode_get_string(dnode, "./source-interface"));
	vty_out(vty, "\n");
}

int bgp_nb_bmp_connect_leaf_modify(struct nb_cb_modify_args *args)
{
	const struct lyd_node *sess;

	sess = yang_dnode_get_parent(args->dnode, "session-list");
	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_nb_bmp_connect_validate(sess, args->errmsg, args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	return bgp_nb_bmp_connect_apply(sess);
}

int bgp_nb_bmp_connect_leaf_destroy(struct nb_cb_destroy_args *args)
{
	const struct lyd_node *sess;

	/*
	 * The destroyed leaf is still present on the running session node.
	 * Validate and apply the candidate session, which no longer has it.
	 * If the session itself is being deleted, its destroy drops the
	 * connection and there is nothing to reapply.
	 */
	sess = bgp_nb_candidate_match(yang_dnode_get_parent(args->dnode, "session-list"));
	switch (args->event) {
	case NB_EV_VALIDATE:
		if (!sess)
			return NB_OK;
		return bgp_nb_bmp_connect_validate(sess, args->errmsg, args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (!sess)
		return NB_OK;
	return bgp_nb_bmp_connect_apply(sess);
}

int bgp_nb_bmp_import_vrf_create(struct nb_cb_create_args *args)
{
	const struct lyd_node *cpp;
	const char *vrfname;
	const char *inst_name;
	void *bt;

	vrfname = yang_dnode_get_string(args->dnode, NULL);

	switch (args->event) {
	case NB_EV_VALIDATE:
		/*
		 * Self-import check from YANG instance identity only — never
		 * from operational bt->bgp.
		 */
		cpp = yang_dnode_get_parent(args->dnode, "control-plane-protocol");
		if (!cpp) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "BMP target BGP instance not found in YANG");
			return NB_ERR_VALIDATION;
		}
		inst_name = yang_dnode_get_string(cpp, "./name");
		if (strmatch(inst_name, vrfname)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "BMP target, can not import our own BGP instance");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	if (!bmp_nb_cb || !bmp_nb_cb->import_vrf_set)
		return NB_OK;

	bt = nb_running_get_entry(args->dnode, NULL, true);
	if (!bt)
		return NB_ERR_NOT_FOUND;

	return bmp_nb_cb->import_vrf_set(bt, vrfname);
}

int bgp_nb_bmp_import_vrf_destroy(struct nb_cb_destroy_args *args)
{
	void *bt;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	if (!bmp_nb_cb || !bmp_nb_cb->import_vrf_unset)
		return NB_OK;

	bt = nb_running_get_entry(args->dnode, NULL, true);
	if (!bt)
		return NB_OK;

	return bmp_nb_cb->import_vrf_unset(bt, yang_dnode_get_string(args->dnode, NULL));
}

void bgp_nb_cli_show_bmp_import_vrf(struct vty *vty, const struct lyd_node *dnode,
				    bool show_defaults)
{
	vty_out(vty, "  bmp import-vrf-view %s\n", yang_dnode_get_string(dnode, NULL));
}

int bgp_nb_bmp_monitor_modify(struct nb_cb_modify_args *args)
{
	const struct lyd_node *af;
	const char *name;
	afi_t afi;
	safi_t safi;
	void *bt;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	if (!bmp_nb_cb || !bmp_nb_cb->monitor_set)
		return NB_OK;

	bt = nb_running_get_entry(args->dnode, NULL, true);
	if (!bt)
		return NB_ERR_NOT_FOUND;

	af = yang_dnode_get_parent(args->dnode, "afi-safi");
	if (!af)
		return NB_ERR_NOT_FOUND;

	name = yang_dnode_get_string(af, "./afi-safi-name");
	yang_afi_safi_identity2value(name, &afi, &safi);
	bmp_nb_cb->monitor_set(bt, afi, safi, args->dnode->schema->name,
			       yang_dnode_get_bool(args->dnode, NULL));
	return NB_OK;
}

int bgp_nb_bmp_monitor_destroy(struct nb_cb_destroy_args *args)
{
	const struct lyd_node *af;
	const char *name;
	afi_t afi;
	safi_t safi;
	void *bt;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	if (!bmp_nb_cb || !bmp_nb_cb->monitor_set)
		return NB_OK;

	bt = nb_running_get_entry(args->dnode, NULL, true);
	if (!bt)
		return NB_OK;

	af = yang_dnode_get_parent(args->dnode, "afi-safi");
	if (!af)
		return NB_OK;

	name = yang_dnode_get_string(af, "./afi-safi-name");
	yang_afi_safi_identity2value(name, &afi, &safi);
	bmp_nb_cb->monitor_set(bt, afi, safi, args->dnode->schema->name, false);
	return NB_OK;
}

void bgp_nb_cli_show_bmp_monitor(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const struct lyd_node *af;
	const char *name;
	afi_t afi;
	safi_t safi;
	const char *policy;

	if (!yang_dnode_get_bool(dnode, NULL))
		return;

	af = yang_dnode_get_parent(dnode, "afi-safi");
	if (!af)
		return;

	name = yang_dnode_get_string(af, "./afi-safi-name");
	yang_afi_safi_identity2value(name, &afi, &safi);

	if (strmatch(dnode->schema->name, "pre-policy"))
		policy = "pre-policy";
	else if (strmatch(dnode->schema->name, "post-policy"))
		policy = "post-policy";
	else
		policy = "loc-rib";

	vty_out(vty, "  bmp monitor %s %s %s\n", afi2str_lower(afi), safi2str(safi), policy);
}


/* Daemon-wide (/frr-bgp:bgp-daemon) CONFIG_NODE callbacks */

int bgp_nb_daemon_no_rib_modify(struct nb_cb_modify_args *args)
{
	bool set;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	set = yang_dnode_get_bool(args->dnode, NULL);
	if (set)
		bgp_option_norib_set_runtime();
	else
		bgp_option_norib_unset_runtime();
	return NB_OK;
}

void bgp_nb_cli_show_daemon_no_rib(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "bgp no-rib\n");
	else if (show_defaults)
		vty_out(vty, "no bgp no-rib\n");
}

int bgp_nb_daemon_session_dscp_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bm->ip_tos = yang_dnode_get_uint8(args->dnode, NULL) << 2;
	return NB_OK;
}

int bgp_nb_daemon_session_dscp_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bm->ip_tos = IPTOS_PREC_INTERNETCONTROL;
	return NB_OK;
}

void bgp_nb_cli_show_daemon_session_dscp(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults)
{
	vty_out(vty, "bgp session-dscp %u\n", yang_dnode_get_uint8(dnode, NULL));
}

int bgp_nb_daemon_inq_limit_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bm->inq_limit = yang_dnode_get_uint32(args->dnode, NULL);
	return NB_OK;
}

int bgp_nb_daemon_inq_limit_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bm->inq_limit = BM_DEFAULT_Q_LIMIT;
	return NB_OK;
}

void bgp_nb_cli_show_daemon_inq_limit(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults)
{
	vty_out(vty, "bgp input-queue-limit %u\n", yang_dnode_get_uint32(dnode, NULL));
}

int bgp_nb_daemon_outq_limit_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bm->outq_limit = yang_dnode_get_uint32(args->dnode, NULL);
	return NB_OK;
}

int bgp_nb_daemon_outq_limit_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bm->outq_limit = BM_DEFAULT_Q_LIMIT;
	return NB_OK;
}

void bgp_nb_cli_show_daemon_outq_limit(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults)
{
	vty_out(vty, "bgp output-queue-limit %u\n", yang_dnode_get_uint32(dnode, NULL));
}

int bgp_nb_daemon_suppress_fib_modify(struct nb_cb_modify_args *args)
{
	bool set;
	uint16_t delay = BGP_DEFAULT_SUPPRESS_FIB_ADV_DELAY;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	set = yang_dnode_get_bool(args->dnode, NULL);
	if (set && yang_dnode_exists(args->dnode, "../suppress-fib-pending-delay"))
		delay = yang_dnode_get_uint16(args->dnode, "../suppress-fib-pending-delay");
	else if (set)
		delay = bm->suppress_fib_adv_delay;

	bm_wait_for_fib_set(set, delay);
	return NB_OK;
}

void bgp_nb_cli_show_daemon_suppress_fib(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults)
{
	/*
	 * CLI always stores delay (YANG default 1000). nb_cli_show_dnode_cmds
	 * skips the default-valued delay leaf, so its cli_show never runs.
	 * Print the enable form here when delay is absent OR at default.
	 */
	if (yang_dnode_get_bool(dnode, NULL)) {
		if (!yang_dnode_exists(dnode, "../suppress-fib-pending-delay") ||
		    yang_dnode_is_default(dnode, "../suppress-fib-pending-delay"))
			vty_out(vty, "bgp suppress-fib-pending\n");
	} else if (show_defaults)
		vty_out(vty, "no bgp suppress-fib-pending\n");
}

int bgp_nb_daemon_suppress_fib_delay_modify(struct nb_cb_modify_args *args)
{
	uint16_t delay;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	delay = yang_dnode_get_uint16(args->dnode, NULL);
	if (bm->wait_for_fib)
		bm_wait_for_fib_set(true, delay);
	else
		bm->suppress_fib_adv_delay = delay;
	return NB_OK;
}

int bgp_nb_daemon_suppress_fib_delay_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bm->suppress_fib_adv_delay = BGP_DEFAULT_SUPPRESS_FIB_ADV_DELAY;
	return NB_OK;
}

void bgp_nb_cli_show_daemon_suppress_fib_delay(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults)
{
	uint16_t delay;
	const struct lyd_node *parent;

	parent = yang_dnode_get_parent(dnode, "bgp-daemon");
	if (!parent || !yang_dnode_get_bool(parent, "suppress-fib-pending"))
		return;

	delay = yang_dnode_get_uint16(dnode, NULL);
	if (delay != BGP_DEFAULT_SUPPRESS_FIB_ADV_DELAY)
		vty_out(vty, "bgp suppress-fib-pending %u\n", delay);
	else
		vty_out(vty, "bgp suppress-fib-pending\n");
}

int bgp_nb_daemon_ipv6_auto_ra_modify(struct nb_cb_modify_args *args)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;
	bool allow;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	allow = yang_dnode_get_bool(args->dnode, NULL);
	COND_FLAG(bm->flags, BM_FLAG_IPV6_NO_AUTO_RA, !allow);
	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp))
		COND_FLAG(bgp->flags, BGP_FLAG_IPV6_NO_AUTO_RA, !allow);
	return NB_OK;
}

void bgp_nb_cli_show_daemon_ipv6_auto_ra(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "no bgp ipv6-auto-ra\n");
	else if (show_defaults)
		vty_out(vty, "bgp ipv6-auto-ra\n");
}

static int bgp_nb_daemon_update_delay_apply(struct nb_cb_modify_args *args, uint16_t delay,
					    uint16_t wait)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;

	if (args->event == NB_EV_VALIDATE) {
		/*
		 * Reject if any BGP instance has per-vrf update-delay in the
		 * candidate tree. delay vs establish-wait is YANG must.
		 */
		if (yang_dnode_exists(
			    args->dnode,
			    "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-config-timers/update-delay-time")) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "global update-delay not permitted with per-vrf update-delay");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bm->v_update_delay = delay;
	bm->v_establish_wait = wait;
	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		bgp->v_update_delay = delay;
		bgp->v_establish_wait = wait;
	}
	return NB_OK;
}

int bgp_nb_daemon_update_delay_modify(struct nb_cb_modify_args *args)
{
	uint16_t delay, wait;
	const struct lyd_node *parent;

	delay = yang_dnode_get_uint16(args->dnode, NULL);
	parent = yang_dnode_get_parent(args->dnode, "bgp-daemon");
	if (parent && yang_dnode_exists(parent, "establish-wait-time"))
		wait = yang_dnode_get_uint16(parent, "establish-wait-time");
	else
		wait = delay;

	return bgp_nb_daemon_update_delay_apply(args, delay, wait);
}

int bgp_nb_daemon_update_delay_destroy(struct nb_cb_destroy_args *args)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bm->v_update_delay = BGP_UPDATE_DELAY_DEFAULT;
	bm->v_establish_wait = bm->v_update_delay;
	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		bgp->v_update_delay = bm->v_update_delay;
		bgp->v_establish_wait = bm->v_establish_wait;
	}
	return NB_OK;
}

void bgp_nb_cli_show_daemon_update_delay(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults)
{
	uint16_t delay, wait;
	const struct lyd_node *parent;

	delay = yang_dnode_get_uint16(dnode, NULL);
	if (delay == BGP_UPDATE_DELAY_DEFAULT && !show_defaults)
		return;

	parent = yang_dnode_get_parent(dnode, "bgp-daemon");
	if (parent && yang_dnode_exists(parent, "establish-wait-time"))
		wait = yang_dnode_get_uint16(parent, "establish-wait-time");
	else
		wait = delay;

	if (delay != wait)
		vty_out(vty, "bgp update-delay %u %u\n", delay, wait);
	else
		vty_out(vty, "bgp update-delay %u\n", delay);
}

int bgp_nb_daemon_establish_wait_modify(struct nb_cb_modify_args *args)
{
	uint16_t delay, wait;
	const struct lyd_node *parent;

	wait = yang_dnode_get_uint16(args->dnode, NULL);
	parent = yang_dnode_get_parent(args->dnode, "bgp-daemon");
	if (parent && yang_dnode_exists(parent, "update-delay-time"))
		delay = yang_dnode_get_uint16(parent, "update-delay-time");
	else
		delay = wait;

	return bgp_nb_daemon_update_delay_apply(args, delay, wait);
}

int bgp_nb_daemon_establish_wait_destroy(struct nb_cb_destroy_args *args)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* update-delay destroy resets both; keep establish-wait aligned. */
	bm->v_establish_wait = bm->v_update_delay;
	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp))
		bgp->v_establish_wait = bm->v_establish_wait;
	return NB_OK;
}

int bgp_nb_daemon_advertisement_delay_modify(struct nb_cb_modify_args *args)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;
	uint16_t delay;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	delay = yang_dnode_get_uint16(args->dnode, NULL);
	bm->v_advertisement_delay = delay;
	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp))
		bgp->v_advertisement_delay = delay;
	return NB_OK;
}

int bgp_nb_daemon_advertisement_delay_destroy(struct nb_cb_destroy_args *args)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bm->v_advertisement_delay = BGP_ADVERTISEMENT_DELAY_DEFAULT;
	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		bgp->v_advertisement_delay = BGP_ADVERTISEMENT_DELAY_DEFAULT;
		if (bgp->advertisement_delay_started && !bgp->advertisement_delay_over) {
			event_cancel(&bgp->t_advertisement_delay);
			bgp->advertisement_delay_started = 0;
			bgp->advertisement_delay_over = 0;
			if (!bgp_update_delay_active(bgp) && !bgp->main_zebra_update_hold) {
				bgp->main_peers_update_hold = 0;
				bgp_start_routeadv(bgp);
			}
		} else {
			event_cancel(&bgp->t_advertisement_delay);
			bgp->advertisement_delay_started = 0;
			bgp->advertisement_delay_over = 0;
		}
	}
	return NB_OK;
}

void bgp_nb_cli_show_daemon_advertisement_delay(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults)
{
	uint16_t delay = yang_dnode_get_uint16(dnode, NULL);

	if (delay != BGP_ADVERTISEMENT_DELAY_DEFAULT || show_defaults)
		vty_out(vty, "bgp advertisement-delay %u\n", delay);
}


static int bgp_nb_daemon_community_alias_validate_format(const char *community, char *errmsg,
							 size_t errmsg_len)
{
	struct community *comm;
	struct lcommunity *lcomm;
	uint8_t invalid = 0;

	/* Value shape only — uniqueness is YANG unique "alias". */
	comm = community_str2com(community);
	if (!comm)
		invalid++;
	community_free(&comm);
	lcomm = lcommunity_str2com(community);
	if (!lcomm)
		invalid++;
	lcommunity_free(&lcomm);
	if (invalid > 1) {
		snprintfrr(errmsg, errmsg_len, "Invalid community format");
		return NB_ERR_VALIDATION;
	}
	return NB_OK;
}

int bgp_nb_daemon_community_alias_create(struct nb_cb_create_args *args)
{
	const char *community;

	if (args->event == NB_EV_VALIDATE) {
		community = yang_dnode_get_string(args->dnode, "./community");
		return bgp_nb_daemon_community_alias_validate_format(community, args->errmsg,
								     args->errmsg_len);
	}

	/* Runtime hashes are updated when the mandatory alias leaf is set. */
	return NB_OK;
}

int bgp_nb_daemon_community_alias_destroy(struct nb_cb_destroy_args *args)
{
	struct community_alias ca = {};
	const char *community;
	const char *alias;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	community = yang_dnode_get_string(args->dnode, "./community");
	alias = yang_dnode_exists(args->dnode, "./alias")
			? yang_dnode_get_string(args->dnode, "./alias")
			: "";
	strlcpy(ca.community, community, sizeof(ca.community));
	strlcpy(ca.alias, alias, sizeof(ca.alias));
	bgp_ca_alias_delete(&ca);
	bgp_ca_community_delete(&ca);
	return NB_OK;
}

void bgp_nb_cli_show_daemon_community_alias(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults)
{
	vty_out(vty, "bgp community alias %s %s\n", yang_dnode_get_string(dnode, "./community"),
		yang_dnode_get_string(dnode, "./alias"));
}

int bgp_nb_daemon_community_alias_name_modify(struct nb_cb_modify_args *args)
{
	struct community_alias ca = {};
	struct community_alias *old;
	const struct lyd_node *parent;
	const char *community;
	const char *alias;

	parent = yang_dnode_get_parent(args->dnode, "community-alias");
	community = yang_dnode_get_string(parent, "./community");
	alias = yang_dnode_get_string(args->dnode, NULL);

	if (args->event == NB_EV_VALIDATE)
		return bgp_nb_daemon_community_alias_validate_format(community, args->errmsg,
								     args->errmsg_len);

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	strlcpy(ca.community, community, sizeof(ca.community));
	old = bgp_ca_community_lookup(&ca);
	if (old) {
		bgp_ca_alias_delete(old);
		bgp_ca_community_delete(old);
	}
	strlcpy(ca.alias, alias, sizeof(ca.alias));
	bgp_ca_alias_insert(&ca);
	bgp_ca_community_insert(&ca);
	return NB_OK;
}

int bgp_nb_daemon_send_extra_data_modify(struct nb_cb_modify_args *args)
{
	bool set;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	set = yang_dnode_get_bool(args->dnode, NULL);
	if (set)
		SET_FLAG(bm->flags, BM_FLAG_SEND_EXTRA_DATA_TO_ZEBRA);
	else
		UNSET_FLAG(bm->flags, BM_FLAG_SEND_EXTRA_DATA_TO_ZEBRA);
	return NB_OK;
}

void bgp_nb_cli_show_daemon_send_extra_data(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "bgp send-extra-data zebra\n");
	else if (show_defaults)
		vty_out(vty, "no bgp send-extra-data zebra\n");
}

int bgp_nb_daemon_snmp_traps_rfc4273_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bm->options, BGP_OPT_TRAPS_RFC4273);
	else
		UNSET_FLAG(bm->options, BGP_OPT_TRAPS_RFC4273);
	return NB_OK;
}

void bgp_nb_cli_show_daemon_snmp_traps_rfc4273(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "no bgp snmp traps rfc4273\n");
	else if (show_defaults)
		vty_out(vty, "bgp snmp traps rfc4273\n");
}

int bgp_nb_daemon_snmp_traps_bgp4_mibv2_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bm->options, BGP_OPT_TRAPS_BGP4MIBV2);
	else
		UNSET_FLAG(bm->options, BGP_OPT_TRAPS_BGP4MIBV2);
	return NB_OK;
}

void bgp_nb_cli_show_daemon_snmp_traps_bgp4_mibv2(struct vty *vty, const struct lyd_node *dnode,
						  bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "bgp snmp traps bgp4-mibv2\n");
	else if (show_defaults)
		vty_out(vty, "no bgp snmp traps bgp4-mibv2\n");
}

int bgp_nb_daemon_snmp_traps_rfc4382_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bm->options, BGP_OPT_TRAPS_RFC4382);
	else
		UNSET_FLAG(bm->options, BGP_OPT_TRAPS_RFC4382);
	return NB_OK;
}

void bgp_nb_cli_show_daemon_snmp_traps_rfc4382(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "no bgp snmp traps rfc4382\n");
	else if (show_defaults)
		vty_out(vty, "bgp snmp traps rfc4382\n");
}

int bgp_nb_daemon_rmap_delay_time_modify(struct nb_cb_modify_args *args)
{
	uint16_t timer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	timer = yang_dnode_get_uint16(args->dnode, NULL);
	bm->rmap_update_timer = timer;

	if (!timer && event_is_scheduled(bm->t_rmap_update)) {
		event_cancel(&bm->t_rmap_update);
		event_execute(bm->master, bgp_route_map_update_timer, NULL, 0, NULL);
	}
	return NB_OK;
}

int bgp_nb_daemon_rmap_delay_time_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bm->rmap_update_timer = RMAP_DEFAULT_UPDATE_TIMER;
	return NB_OK;
}

void bgp_nb_cli_show_daemon_rmap_delay_time(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults)
{
	uint16_t timer = yang_dnode_get_uint16(dnode, NULL);

	if (timer != RMAP_DEFAULT_UPDATE_TIMER || show_defaults)
		vty_out(vty, "bgp route-map delay-timer %u\n", timer);
}

/* Daemon-wide CONFIG_NODE graceful-restart / graceful-shutdown */

static bool bgp_nb_daemon_gr_per_vrf_conflict(const struct lyd_node *dnode, char *errmsg,
					      size_t errmsg_len)
{
	/*
	 * Mutual exclusion vs per-instance GR mode from candidate YANG only.
	 * Default helper mode has neither enabled nor graceful-restart-disable.
	 */
	if (yang_dnode_exists(dnode, BGP_NB_INST_GR_ENABLED_XPATH) ||
	    yang_dnode_exists(dnode, BGP_NB_INST_GR_DISABLE_XPATH)) {
		if (errmsg && errmsg_len)
			snprintfrr(errmsg, errmsg_len,
				   "global graceful-restart not permitted with per-vrf configuration");
		return true;
	}
	return false;
}

static int bgp_nb_daemon_gr_mode_apply(bool on, bool disable, char *errmsg, size_t errmsg_len)
{
	if (bgp_global_gr_config(on, disable, errmsg, errmsg_len) != BGP_GR_SUCCESS)
		return NB_ERR;
	return NB_OK;
}

int bgp_nb_daemon_gr_enabled_modify(struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_VALIDATE) {
		if (!yang_dnode_get_bool(args->dnode, NULL))
			return NB_OK;
		if (bgp_nb_daemon_gr_per_vrf_conflict(args->dnode, args->errmsg, args->errmsg_len))
			return NB_ERR_VALIDATION;
		return NB_OK;
	}

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	return bgp_nb_daemon_gr_mode_apply(yang_dnode_get_bool(args->dnode, NULL), false, args->errmsg,
					  args->errmsg_len);
}

int bgp_nb_daemon_gr_enabled_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	return bgp_nb_daemon_gr_mode_apply(false, false, args->errmsg, args->errmsg_len);
}

void bgp_nb_cli_show_daemon_gr_enabled(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "bgp graceful-restart\n");
}

int bgp_nb_daemon_gr_disable_modify(struct nb_cb_modify_args *args)
{
	struct listnode *node, *nnode;
	struct listnode *pnode, *pnnode;
	struct bgp *bgp;
	struct peer *peer;
	int ret;

	if (args->event == NB_EV_VALIDATE) {
		if (!yang_dnode_get_bool(args->dnode, NULL))
			return NB_OK;
		if (bgp_nb_daemon_gr_per_vrf_conflict(args->dnode, args->errmsg, args->errmsg_len))
			return NB_ERR_VALIDATION;
		return NB_OK;
	}

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	if (!yang_dnode_get_bool(args->dnode, NULL))
		return bgp_nb_daemon_gr_mode_apply(false, true, args->errmsg, args->errmsg_len);

	ret = bgp_nb_daemon_gr_mode_apply(true, true, args->errmsg, args->errmsg_len);
	if (ret != NB_OK)
		return ret;

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		for (ALL_LIST_ELEMENTS(bgp->peer, pnode, pnnode, peer)) {
			bgp_capability_send(peer->connection, AFI_IP, SAFI_UNICAST,
					    CAPABILITY_CODE_RESTART, CAPABILITY_ACTION_UNSET);
			bgp_capability_send(peer->connection, AFI_IP, SAFI_UNICAST,
					    CAPABILITY_CODE_LLGR, CAPABILITY_ACTION_UNSET);
		}
	}
	return NB_OK;
}

int bgp_nb_daemon_gr_disable_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	return bgp_nb_daemon_gr_mode_apply(false, true, args->errmsg, args->errmsg_len);
}

void bgp_nb_cli_show_daemon_gr_disable(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "bgp graceful-restart-disable\n");
}

int bgp_nb_daemon_gr_stale_routes_time_modify(struct nb_cb_modify_args *args)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;
	uint16_t val;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	val = yang_dnode_get_uint16(args->dnode, NULL);
	bm->stalepath_time = val;
	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp))
		bgp->stalepath_time = val;
	return NB_OK;
}

void bgp_nb_cli_show_daemon_gr_stale_routes_time(struct vty *vty, const struct lyd_node *dnode,
						 bool show_defaults)
{
	uint16_t val = yang_dnode_get_uint16(dnode, NULL);

	if (val != BGP_DEFAULT_STALEPATH_TIME || show_defaults)
		vty_out(vty, "bgp graceful-restart stalepath-time %u\n", val);
}

int bgp_nb_daemon_gr_restart_time_modify(struct nb_cb_modify_args *args)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;
	uint16_t val;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	val = yang_dnode_get_uint16(args->dnode, NULL);
	bm->restart_time = val;
	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		bgp->restart_time = val;
		bgp_nb_gr_restart_time_peers(bgp, false);
	}
	return NB_OK;
}

void bgp_nb_cli_show_daemon_gr_restart_time(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults)
{
	uint16_t val = yang_dnode_get_uint16(dnode, NULL);

	if (val != BGP_DEFAULT_RESTART_TIME || show_defaults)
		vty_out(vty, "bgp graceful-restart restart-time %u\n", val);
}

int bgp_nb_daemon_gr_select_defer_time_modify(struct nb_cb_modify_args *args)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;
	uint16_t defer_time;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	defer_time = yang_dnode_get_uint16(args->dnode, NULL);
	bm->select_defer_time = defer_time;
	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		bgp->select_defer_time = defer_time;
		if (defer_time == 0)
			SET_FLAG(bgp->flags, BGP_FLAG_SELECT_DEFER_DISABLE);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_SELECT_DEFER_DISABLE);
	}
	return NB_OK;
}

void bgp_nb_cli_show_daemon_gr_select_defer_time(struct vty *vty, const struct lyd_node *dnode,
						 bool show_defaults)
{
	uint16_t val = yang_dnode_get_uint16(dnode, NULL);

	if (val != BGP_DEFAULT_SELECT_DEFERRAL_TIME || show_defaults)
		vty_out(vty, "bgp graceful-restart select-defer-time %u\n", val);
}

int bgp_nb_daemon_gr_rib_stale_time_modify(struct nb_cb_modify_args *args)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;
	uint16_t val;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	val = yang_dnode_get_uint16(args->dnode, NULL);
	bm->rib_stale_time = val;
	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		bgp->rib_stale_time = val;
		bgp_zebra_stale_timer_update(bgp);
	}
	return NB_OK;
}

void bgp_nb_cli_show_daemon_gr_rib_stale_time(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults)
{
	uint16_t val = yang_dnode_get_uint16(dnode, NULL);

	if (val != BGP_DEFAULT_RIB_STALE_TIME || show_defaults)
		vty_out(vty, "bgp graceful-restart rib-stale-time %u\n", val);
}

int bgp_nb_daemon_gr_preserve_fw_modify(struct nb_cb_modify_args *args)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;
	bool set;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	set = yang_dnode_get_bool(args->dnode, NULL);
	if (set)
		SET_FLAG(bm->flags, BM_FLAG_GR_PRESERVE_FWD);
	else
		UNSET_FLAG(bm->flags, BM_FLAG_GR_PRESERVE_FWD);

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		if (set)
			SET_FLAG(bgp->flags, BGP_FLAG_GR_PRESERVE_FWD);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_GR_PRESERVE_FWD);
	}
	return NB_OK;
}

void bgp_nb_cli_show_daemon_gr_preserve_fw(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "bgp graceful-restart preserve-fw-state\n");
	else if (show_defaults)
		vty_out(vty, "no bgp graceful-restart preserve-fw-state\n");
}

int bgp_nb_daemon_graceful_shutdown_modify(struct nb_cb_modify_args *args)
{
	bool enable;

	enable = yang_dnode_get_bool(args->dnode, NULL);

	if (args->event == NB_EV_VALIDATE) {
		if (!enable)
			return NB_OK;
		if (yang_dnode_exists(args->dnode, BGP_NB_INST_GSHUT_XPATH)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "global graceful-shutdown not permitted with per-vrf graceful-shutdown");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	if (bgp_global_graceful_shutdown_set(enable, args->errmsg, args->errmsg_len) !=
	    BGP_GR_SUCCESS)
		return NB_ERR;
	return NB_OK;
}

void bgp_nb_cli_show_daemon_graceful_shutdown(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "bgp graceful-shutdown\n");
	else if (show_defaults)
		vty_out(vty, "no bgp graceful-shutdown\n");
}

/*
 * XPath: /frr-interface:lib/frr-interface:interface/frr-bgp:mpls-bgp-forwarding
 */
int lib_interface_mpls_bgp_forwarding_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct bgp_interface *iifp;
	bool enable;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		if (!ifp)
			return NB_ERR_NOT_FOUND;

		iifp = ifp->info;
		if (!iifp)
			return NB_OK;

		enable = yang_dnode_get_bool(args->dnode, NULL);
		if (enable == !!CHECK_FLAG(iifp->flags, BGP_INTERFACE_MPLS_BGP_FORWARDING))
			break;

		if (enable)
			SET_FLAG(iifp->flags, BGP_INTERFACE_MPLS_BGP_FORWARDING);
		else
			UNSET_FLAG(iifp->flags, BGP_INTERFACE_MPLS_BGP_FORWARDING);

		if (if_is_operative(ifp))
			bgp_nht_ifp_up(ifp);
		break;
	}

	return NB_OK;
}

void bgp_nb_cli_show_mpls_bgp_forwarding(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " mpls bgp forwarding\n");
}

/*
 * XPath: /frr-interface:lib/frr-interface:interface/frr-bgp:mpls-l3vpn-multi-domain-switching
 */
int lib_interface_mpls_l3vpn_multi_domain_switching_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct bgp_interface *iifp;
	bool enable;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		if (!ifp)
			return NB_ERR_NOT_FOUND;

		iifp = ifp->info;
		if (!iifp)
			return NB_OK;

		enable = yang_dnode_get_bool(args->dnode, NULL);
		if (enable == !!CHECK_FLAG(iifp->flags, BGP_INTERFACE_MPLS_L3VPN_SWITCHING))
			break;

		if (enable)
			SET_FLAG(iifp->flags, BGP_INTERFACE_MPLS_L3VPN_SWITCHING);
		else
			UNSET_FLAG(iifp->flags, BGP_INTERFACE_MPLS_L3VPN_SWITCHING);

		if (if_is_operative(ifp))
			bgp_nht_ifp_up(ifp);
		break;
	}

	return NB_OK;
}

void bgp_nb_cli_show_mpls_l3vpn_multi_domain_switching(struct vty *vty,
						       const struct lyd_node *dnode,
						       bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " mpls bgp l3vpn-multi-domain-switching\n");
}

/*
 * Destroy / optional callbacks added to satisfy nb_validate_callbacks.
 */

int bgp_nb_as_notation_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp->asnotation = ASNOTATION_PLAIN;
	return NB_OK;
}

int bgp_nb_enforce_first_as_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	struct listnode *node;
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!CHECK_FLAG(bgp->flags, BGP_FLAG_ENFORCE_FIRST_AS))
		return NB_OK;
	UNSET_FLAG(bgp->flags, BGP_FLAG_ENFORCE_FIRST_AS);
	for (ALL_LIST_ELEMENTS_RO(bgp->peer, node, peer)) {
		FOREACH_AFI_SAFI (afi, safi)
			peer_on_policy_change(peer, afi, safi, 0);
	}
	return NB_OK;
}

int bgp_nb_hard_admin_reset_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	UNSET_FLAG(bgp->flags, BGP_FLAG_HARD_ADMIN_RESET);
	return NB_OK;
}

int bgp_nb_multi_path_as_set_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	UNSET_FLAG(bgp->flags, BGP_FLAG_MULTIPATH_RELAX_AS_SET);
	bgp_recalculate_all_bestpaths(bgp);
	return NB_OK;
}

int bgp_nb_gr_llgr_stale_time_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	struct listnode *node, *nnode;
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp->llgr_stale_time = BGP_DEFAULT_LLGR_STALE_TIME;
	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer))
		bgp_capability_send(peer->connection, AFI_IP, SAFI_UNICAST, CAPABILITY_CODE_LLGR,
				    CAPABILITY_ACTION_SET);
	return NB_OK;
}

int bgp_nb_maxpaths_ibgp_cluster_destroy(struct nb_cb_destroy_args *args)
{
	const struct lyd_node *ibgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ibgp = yang_dnode_get_parent(args->dnode, "ibgp");
	if (!ibgp || !yang_dnode_exists(ibgp, "./maximum-paths"))
		return NB_OK;

	return bgp_nb_maxpaths_apply(yang_dnode_get(ibgp, "./maximum-paths"), BGP_PEER_IBGP, false);
}

int bgp_nb_peer_shutdown_enable_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_OK;

	peer_tx_shutdown_message_unset(peer);
	peer_flag_unset(peer, PEER_FLAG_SHUTDOWN);
	return NB_OK;
}

int bgp_nb_peer_local_role_strict_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_OK;

	/*
	 * Only clear strict-mode. Do not call bgp_nb_peer_local_role_apply():
	 * "no neighbor … local-role" destroys strict-mode and role together,
	 * and apply order can unset the role first — re-apply from the old
	 * dnode would resurrect the role and leave the capability advertised.
	 */
	if (CHECK_FLAG(peer->flags, PEER_FLAG_ROLE))
		peer_role_set(peer, peer->local_role, false);
	return NB_OK;
}

int bgp_nb_peer_bfd_detect_mult_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !peer->bfd_config)
		return NB_OK;

	peer->bfd_config->detection_multiplier = BFD_DEF_DETECT_MULT;
	bgp_nb_peer_bfd_apply(peer);
	return NB_OK;
}

int bgp_nb_peer_bfd_min_rx_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !peer->bfd_config)
		return NB_OK;

	peer->bfd_config->min_rx = BFD_DEF_MIN_RX;
	bgp_nb_peer_bfd_apply(peer);
	return NB_OK;
}

int bgp_nb_peer_bfd_min_tx_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !peer->bfd_config)
		return NB_OK;

	peer->bfd_config->min_tx = BFD_DEF_MIN_TX;
	bgp_nb_peer_bfd_apply(peer);
	return NB_OK;
}

int bgp_nb_peer_bfd_cbit_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !peer->bfd_config)
		return NB_OK;

	peer->bfd_config->cbit = false;
	bgp_nb_peer_bfd_apply(peer);
	return NB_OK;
}

int bgp_nb_peer_bfd_session_type_modify(struct nb_cb_modify_args *args)
{
	/* Stored for future BFD hop-type wiring; accept config for now. */
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return NB_OK;
}

int bgp_nb_peer_bfd_session_type_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return NB_OK;
}

int bgp_nb_aggregate_attr_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_aggregate_apply(yang_dnode_get_parent(args->dnode, "aggregate-route"));
}

int bgp_nb_aggregate_attr_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_aggregate_apply(yang_dnode_get_parent(args->dnode, "aggregate-route"));
}

int bgp_nb_connect_retry_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp_nb_apply_global_timers(bgp, args->dnode);
	return NB_OK;
}

int bgp_nb_daemon_gr_notification_modify(struct nb_cb_modify_args *args)
{
	struct listnode *node, *nnode;
	struct listnode *pnode, *pnnode;
	struct bgp *bgp;
	struct peer *peer;
	bool enable;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	enable = yang_dnode_get_bool(args->dnode, NULL);
	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		if (enable)
			SET_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_NOTIFICATION);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_NOTIFICATION);
		for (ALL_LIST_ELEMENTS(bgp->peer, pnode, pnnode, peer))
			bgp_capability_send(peer->connection, AFI_IP, SAFI_UNICAST,
					    CAPABILITY_CODE_RESTART, CAPABILITY_ACTION_SET);
	}
	return NB_OK;
}

int bgp_nb_daemon_gr_notification_destroy(struct nb_cb_destroy_args *args)
{
	struct listnode *node, *nnode;
	struct listnode *pnode, *pnnode;
	struct bgp *bgp;
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		UNSET_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_NOTIFICATION);
		for (ALL_LIST_ELEMENTS(bgp->peer, pnode, pnnode, peer))
			bgp_capability_send(peer->connection, AFI_IP, SAFI_UNICAST,
					    CAPABILITY_CODE_RESTART, CAPABILITY_ACTION_SET);
	}
	return NB_OK;
}

void bgp_nb_cli_show_daemon_gr_notification(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "bgp graceful-restart notification\n");
	else
		vty_out(vty, "no bgp graceful-restart notification\n");
}

int bgp_nb_daemon_gr_disable_eor_modify(struct nb_cb_modify_args *args)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;
	bool enable;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	enable = yang_dnode_get_bool(args->dnode, NULL);
	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		if (enable)
			SET_FLAG(bgp->flags, BGP_FLAG_GR_DISABLE_EOR);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_GR_DISABLE_EOR);
	}
	return NB_OK;
}

void bgp_nb_cli_show_daemon_gr_disable_eor(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "bgp graceful-restart disable-eor\n");
	else if (show_defaults)
		vty_out(vty, "no bgp graceful-restart disable-eor\n");
}

int bgp_nb_daemon_gr_llgr_stale_time_modify(struct nb_cb_modify_args *args)
{
	struct listnode *node, *nnode;
	struct listnode *pnode, *pnnode;
	struct bgp *bgp;
	struct peer *peer;
	uint32_t val;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	val = yang_dnode_get_uint32(args->dnode, NULL);
	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		bgp->llgr_stale_time = val;
		for (ALL_LIST_ELEMENTS(bgp->peer, pnode, pnnode, peer))
			bgp_capability_send(peer->connection, AFI_IP, SAFI_UNICAST,
					    CAPABILITY_CODE_LLGR, CAPABILITY_ACTION_SET);
	}
	return NB_OK;
}

int bgp_nb_daemon_gr_llgr_stale_time_destroy(struct nb_cb_destroy_args *args)
{
	struct listnode *node, *nnode;
	struct listnode *pnode, *pnnode;
	struct bgp *bgp;
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		bgp->llgr_stale_time = BGP_DEFAULT_LLGR_STALE_TIME;
		for (ALL_LIST_ELEMENTS(bgp->peer, pnode, pnnode, peer))
			bgp_capability_send(peer->connection, AFI_IP, SAFI_UNICAST,
					    CAPABILITY_CODE_LLGR, CAPABILITY_ACTION_SET);
	}
	return NB_OK;
}

void bgp_nb_cli_show_daemon_gr_llgr_stale_time(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults)
{
	uint32_t val = yang_dnode_get_uint32(dnode, NULL);

	if (val != BGP_DEFAULT_LLGR_STALE_TIME || show_defaults)
		vty_out(vty, "bgp long-lived-graceful-restart stale-time %u\n", val);
}
