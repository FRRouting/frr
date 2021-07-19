/*
 * Static daemon BFD integration.
 *
 * Copyright (C) 2020 Network Device Education Foundation, Inc. ("NetDEF")
 *                    Rafael F. Zalamena
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA.
 */

#include <zebra.h>

#include "lib/printfrr.h"
#include "lib/srcdest_table.h"

#include "staticd/static_routes.h"
#include "staticd/static_zebra.h"

#include "lib/openbsd-queue.h"

DEFINE_MTYPE_STATIC(STATIC, ROUTE_GROUP, "route group memory usage");
DEFINE_MTYPE_STATIC(STATIC, ROUTE_GROUP_MEMBER,
		    "route group member memory usage");

/** Global static BFD integration variables. */
struct static_bfd_global {
	/** Static route group list. */
	struct srglist sbg_srglist;
};

static struct static_bfd_global sbglobal;

/*
 * Next hop BFD monitoring settings.
 */
static void static_next_hop_bfd_change(struct static_nexthop *sn,
				       const struct bfd_session_status *bss)
{
	switch (bss->state) {
	case BSS_UNKNOWN:
		/* FALLTHROUGH: no known state yet. */
	case BSS_ADMIN_DOWN:
		/* NOTHING: we or the remote end administratively shutdown. */
		break;
	case BSS_DOWN:
		/* Peer went down, remove this next hop. */
		zlog_info("%s: next hop is down, remove it from RIB", __func__);
		sn->path_down = true;
		static_zebra_route_add(sn->rn, sn->sp, sn->safi, true);
		break;
	case BSS_UP:
		/* Peer is back up, add this next hop. */
		zlog_info("%s: next hop is up, add it to RIB", __func__);
		sn->path_down = false;
		static_zebra_route_add(sn->rn, sn->sp, sn->safi, true);
		break;
	}
}

static void static_next_hop_bfd_updatecb(
	__attribute__((unused)) struct bfd_session_params *bsp,
	const struct bfd_session_status *bss, void *arg)
{
	static_next_hop_bfd_change(arg, bss);
}

void static_next_hop_bfd_monitor_enable(struct static_nexthop *sn,
					const struct lyd_node *dnode)
{
	bool use_interface;
	bool use_profile;
	bool onlink;
	bool mhop;
	int family;

	use_interface = false;
	use_profile = yang_dnode_exists(dnode, "../profile");
	onlink = yang_dnode_exists(dnode, "../../onlink")
		 && yang_dnode_get_bool(dnode, "../../onlink");
	mhop = yang_dnode_get_bool(dnode, "../multi-hop");

	switch (sn->type) {
	case STATIC_IPV4_GATEWAY_IFNAME:
	case STATIC_IPV6_GATEWAY_IFNAME:
		use_interface = true;
		/* FALLTHROUGH */
	case STATIC_IPV4_GATEWAY:
	case STATIC_IPV6_GATEWAY:
		if (sn->type == STATIC_IPV4_GATEWAY
		    || sn->type == STATIC_IPV4_GATEWAY_IFNAME)
			family = AF_INET;
		else
			family = AF_INET6;
		break;

	case STATIC_IFNAME:
	case STATIC_BLACKHOLE:
	default:
		zlog_err("%s: invalid next hop type", __func__);
		return;
	}

	/* Reconfigure or allocate new memory. */
	if (sn->bsp == NULL)
		sn->bsp = bfd_sess_new(static_next_hop_bfd_updatecb, sn);

	/* Configure the session. TODO source address.*/
	if (family == AF_INET)
		bfd_sess_set_ipv4_addrs(sn->bsp, NULL, &sn->addr.ipv4);
	else
		bfd_sess_set_ipv6_addrs(sn->bsp, NULL, &sn->addr.ipv6);

	bfd_sess_set_interface(sn->bsp, use_interface ? sn->ifname : NULL);

	bfd_sess_set_profile(sn->bsp, use_profile ? yang_dnode_get_string(
					      dnode, "../profile")
						  : NULL);

	if (onlink || mhop == false)
		bfd_sess_set_mininum_ttl(sn->bsp, BFD_SINGLE_HOP_TTL);
	else
		bfd_sess_set_mininum_ttl(sn->bsp, BFD_MULTI_HOP_MIN_TTL);

	/* Install or update the session. */
	bfd_sess_install(sn->bsp);

	/* Update current path status. */
	sn->path_down = (bfd_sess_status(sn->bsp) != BSS_UP);
}

void static_next_hop_bfd_monitor_disable(struct static_nexthop *sn)
{
	bfd_sess_free(&sn->bsp);

	/* Reset path status. */
	sn->path_down = false;
}

void static_next_hop_bfd_multi_hop(struct static_nexthop *sn, bool mhop)
{
	if (sn->bsp == NULL)
		return;

	bfd_sess_set_mininum_ttl(sn->bsp, mhop ? BFD_MULTI_HOP_MIN_TTL
					       : BFD_SINGLE_HOP_TTL);
	bfd_sess_install(sn->bsp);
}

void static_next_hop_bfd_profile(struct static_nexthop *sn, const char *name)
{
	if (sn->bsp == NULL)
		return;

	bfd_sess_set_profile(sn->bsp, name);
	bfd_sess_install(sn->bsp);
}

/*
 * Route group BFD monitoring settings.
 */
static struct static_group_member *
static_group_member_new(struct static_route_group *srg,
			struct static_nexthop *sn)
{
	struct static_group_member *sgm;

	/* Remove next hop specific BFD configuration if any. */
	bfd_sess_free(&sn->bsp);

	sgm = XCALLOC(MTYPE_ROUTE_GROUP_MEMBER, sizeof(*sgm));
	sgm->sgm_sn = sn;
	TAILQ_INSERT_TAIL(&srg->srg_sgmlist, sgm, sgm_entry);

	return sgm;
}

static void static_group_member_free(struct static_group_member **sgm)
{
	struct static_route_group *srg;
	struct static_nexthop *sn;

	if ((*sgm) == NULL)
		return;

	srg = (*sgm)->sgm_srg;

	/* Set default next hop installation status. */
	sn = (*sgm)->sgm_sn;
	if (sn->path_down) {
		sn->path_down = false;
		static_zebra_route_add(sn->rn, sn->sp, sn->safi, true);
	}

	TAILQ_REMOVE(&srg->srg_sgmlist, (*sgm), sgm_entry);
	XFREE(MTYPE_ROUTE_GROUP_MEMBER, (*sgm));
}

static struct static_group_member *
static_group_member_lookup(struct static_route_group *srg,
			   struct static_nexthop *sn)
{
	struct static_group_member *sgm;

	TAILQ_FOREACH (sgm, &srg->srg_sgmlist, sgm_entry) {
		if (sgm->sgm_sn != sn)
			continue;

		return sgm;
	}

	return NULL;
}

struct static_route_group *static_route_group_new(const char *name)
{
	struct static_route_group *srg;

	srg = XCALLOC(MTYPE_ROUTE_GROUP, sizeof(*srg));

	/* Initialize variables. */
	strlcpy(srg->srg_name, name, sizeof(srg->srg_name));

	/* Initialize lists/entries. */
	TAILQ_INIT(&srg->srg_sgmlist);
	TAILQ_INSERT_TAIL(&sbglobal.sbg_srglist, srg, srg_entry);

	return srg;
}

void static_route_group_free(struct static_route_group **srg)
{
	struct static_group_member *sgm;

	if ((*srg) == NULL)
		return;

	/* Free BFD session parameters if any. */
	bfd_sess_free(&(*srg)->srg_bsp);

	/* Remove all members. */
	while ((sgm = TAILQ_FIRST(&(*srg)->srg_sgmlist)) != NULL)
		static_group_member_free(&sgm);

	/* Remove from list and free memory. */
	TAILQ_REMOVE(&sbglobal.sbg_srglist, (*srg), srg_entry);
	XFREE(MTYPE_ROUTE_GROUP, (*srg));
}

static struct static_route_group *static_route_group_lookup(const char *name)
{
	struct static_route_group *srg;

	TAILQ_FOREACH (srg, &sbglobal.sbg_srglist, srg_entry) {
		if (strcmp(srg->srg_name, name))
			continue;

		return srg;
	}

	return NULL;
}

struct static_group_member *
static_group_member_glookup(struct static_nexthop *sn)
{
	struct static_route_group *srg;
	struct static_group_member *srm;

	TAILQ_FOREACH (srg, &sbglobal.sbg_srglist, srg_entry) {
		srm = static_group_member_lookup(srg, sn);
		if (srm == NULL)
			continue;

		return srm;
	}

	return NULL;
}

void static_group_monitor_enable(const char *name, struct static_nexthop *sn)
{
	struct static_route_group *srg;
	struct static_group_member *sgm;

	srg = static_route_group_lookup(name);
	if (srg == NULL)
		srg = static_route_group_new(name);

	sgm = static_group_member_lookup(srg, sn);
	if (sgm != NULL) {
		if (sn->type == STATIC_IPV4_GATEWAY
		    || sn->type == STATIC_IPV4_GATEWAY_IFNAME)
			zlog_err("%s: membership already exists for %pI4",
				 __func__, &sn->addr.ipv4);
		else if (sn->type == STATIC_IPV6_GATEWAY
			 || sn->type == STATIC_IPV6_GATEWAY_IFNAME)
			zlog_err("%s: membership already exists for %pI6",
				 __func__, &sn->addr.ipv6);
		else
			zlog_err("%s: membership already exists", __func__);
		return;
	}

	sgm = static_group_member_new(srg, sn);

	/* Save the pointers. */
	sgm->sgm_sn = sn;
	sgm->sgm_srg = srg;

	/* Apply current status immediately. */
	sn->path_down = (srg->srg_bsp == NULL
			 || bfd_sess_status(srg->srg_bsp) != BSS_UP);
}

void static_group_monitor_disable(const char *name, struct static_nexthop *sn)
{
	struct static_route_group *srg;
	struct static_group_member *sgm;

	/* Look for route group. */
	srg = static_route_group_lookup(name);
	if (srg == NULL) {
		zlog_err("%s: no group named %s", __func__, name);
		return;
	}

	sgm = static_group_member_lookup(srg, sn);
	if (sgm == NULL) {
		zlog_err("%s: unable to find next hop in group %s", __func__,
			 name);
		return;
	}

	static_group_member_free(&sgm);
}

void static_route_group_bfd_vrf(struct static_route_group *srg,
				const char *vrfname)
{
	struct vrf *vrf;

	if (srg->srg_bsp == NULL)
		return;

	vrf = vrf_lookup_by_name(vrfname);
	bfd_sess_set_vrf(srg->srg_bsp, vrf ? vrf->vrf_id : VRF_UNKNOWN);
	bfd_sess_install(srg->srg_bsp);
}

void static_route_group_bfd_addresses(struct static_route_group *srg,
				      const struct lyd_node *dnode)
{
	struct ipaddr ia_src = {}, ia_dst = {};
	struct in6_addr *ia_srcp = NULL;

	if (srg->srg_bsp == NULL)
		return;

	if (yang_dnode_exists(dnode, "../source")) {
		yang_dnode_get_ip(&ia_src, dnode, "../source", NULL);
		ia_srcp = (struct in6_addr *)&ia_src.ip;
	} else
		ia_srcp = NULL;

	yang_dnode_get_ip(&ia_dst, dnode, "../peer", NULL);

	if (ia_dst.ipa_type == IPADDR_V4)
		bfd_sess_set_ipv4_addrs(srg->srg_bsp, (struct in_addr *)ia_srcp,
					(struct in_addr *)&ia_dst.ip);
	else
		bfd_sess_set_ipv6_addrs(srg->srg_bsp,
					(struct in6_addr *)ia_srcp,
					(struct in6_addr *)&ia_dst.ip);

	bfd_sess_install(srg->srg_bsp);
}

void static_route_group_bfd_interface(struct static_route_group *srg,
				      const char *ifname)
{
	if (srg->srg_bsp == NULL)
		return;

	bfd_sess_set_interface(srg->srg_bsp, ifname);
	bfd_sess_install(srg->srg_bsp);
}

static void static_route_group_bfd_updatecb(
	__attribute__((unused)) struct bfd_session_params *bsp,
	const struct bfd_session_status *bss, void *arg)
{
	struct static_route_group *srg = arg;
	struct static_group_member *sgm;

	TAILQ_FOREACH (sgm, &srg->srg_sgmlist, sgm_entry)
		static_next_hop_bfd_change(sgm->sgm_sn, bss);
}

void static_route_group_bfd_enable(struct static_route_group *srg,
				   const struct lyd_node *dnode)
{
	bool use_interface = yang_dnode_exists(dnode, "../interface");
	bool use_profile = yang_dnode_exists(dnode, "../profile");
	bool mhop = yang_dnode_get_bool(dnode, "../multi-hop");

	/* Reconfigure or allocate new memory. */
	if (srg->srg_bsp == NULL)
		srg->srg_bsp =
			bfd_sess_new(static_route_group_bfd_updatecb, srg);

	static_route_group_bfd_addresses(srg, dnode);
	bfd_sess_set_interface(
		srg->srg_bsp,
		use_interface ? yang_dnode_get_string(dnode, "../interface")
			      : NULL);
	bfd_sess_set_profile(srg->srg_bsp, use_profile ? yang_dnode_get_string(
						   dnode, "../profile")
						       : NULL);

	bfd_sess_set_mininum_ttl(srg->srg_bsp, mhop ? BFD_MULTI_HOP_MIN_TTL
						    : BFD_SINGLE_HOP_TTL);

	/* Install or update the session. */
	bfd_sess_install(srg->srg_bsp);
}

void static_route_group_bfd_multi_hop(struct static_route_group *srg, bool mhop)
{
	if (srg->srg_bsp == NULL)
		return;

	bfd_sess_set_mininum_ttl(srg->srg_bsp, mhop ? BFD_MULTI_HOP_MIN_TTL
						    : BFD_SINGLE_HOP_TTL);
	bfd_sess_install(srg->srg_bsp);
}

void static_route_group_bfd_disable(struct static_route_group *srg)
{
	bfd_sess_free(&srg->srg_bsp);
}

void static_route_group_bfd_profile(struct static_route_group *srg,
				    const char *profile)
{
	if (srg->srg_bsp == NULL)
		return;

	bfd_sess_set_profile(srg->srg_bsp, profile);
	bfd_sess_install(srg->srg_bsp);
}

/*
 * Misc.
 */
static void
static_route_group_var(vector comps,
		       __attribute__((unused)) struct cmd_token *token)
{
	struct static_route_group *srg;

	TAILQ_FOREACH (srg, &sbglobal.sbg_srglist, srg_entry)
		vector_set(comps, XSTRDUP(MTYPE_COMPLETION, srg->srg_name));
}

static const struct cmd_variable_handler srg_vars[] = {
	{.tokenname = "STRGRP", .completions = static_route_group_var},
	{.completions = NULL}
};


void static_bfd_initialize(struct zclient *zc, struct thread_master *tm)
{
	/* Initialize list head. */
	TAILQ_INIT(&sbglobal.sbg_srglist);

	/* Initialize BFD integration library. */
	bfd_protocol_integration_init(zc, tm);

	/* Auto complete route groups commands. */
	cmd_variable_handler_register(srg_vars);
}

/*
 * CLI.
 */
static void static_bfd_show_nexthop_json(struct vty *vty,
					 struct json_object *jo,
					 const struct static_nexthop *sn)
{
	const struct prefix *dst_p, *src_p;
	struct json_object *jo_nh;
	char buf[256];

	jo_nh = json_object_new_object();

	srcdest_rnode_prefixes(sn->rn, &dst_p, &src_p);
	if (src_p) {
		snprintfrr(buf, sizeof(buf), "%pFX", src_p);
		json_object_string_add(jo_nh, "from", buf);
	}

	snprintfrr(buf, sizeof(buf), "%pFX", dst_p);
	json_object_string_add(jo_nh, "prefix", buf);
	json_object_string_add(jo_nh, "vrf", sn->nh_vrfname);

	json_object_boolean_add(jo_nh, "installed", !sn->path_down);

	json_object_array_add(jo, jo_nh);
}

static void static_bfd_show_group_json(struct vty *vty, struct json_object *jo)
{
	struct json_object *jo_group, *jo_nharray;
	struct static_group_member *sgm;
	struct static_route_group *srg;
	struct static_nexthop *sn;
	enum bfd_session_state bss;
	const char *vrfname;
	const char *ifname;
	int family;
	uint8_t min_ttl;
	struct in6_addr local, peer;
	char buf[256];

	TAILQ_FOREACH (srg, &sbglobal.sbg_srglist, srg_entry) {
		bss = bfd_sess_status(srg->srg_bsp);
		bfd_sess_addresses(srg->srg_bsp, &family, &local,
					     &peer);
		ifname = bfd_sess_interface(srg->srg_bsp);
		vrfname = bfd_sess_vrf(srg->srg_bsp);
		min_ttl = bfd_sess_minimum_ttl(srg->srg_bsp);

		jo_group = json_object_new_object();
		json_object_string_add(jo_group, "name", srg->srg_name);
		json_object_boolean_add(jo_group, "installed", bss == BSS_UP);
		if (min_ttl != BFD_SINGLE_HOP_TTL) {
			if (family == AF_INET)
				snprintfrr(buf, sizeof(buf), "%pI4",
					   (struct in_addr *)&local);
			else
				snprintfrr(buf, sizeof(buf), "%pI6", &local);

			json_object_boolean_add(jo_group, "multi-hop", true);
			json_object_string_add(jo_group, "source", buf);
		} else
			json_object_boolean_add(jo_group, "multi-hop", false);

		if (family == AF_INET)
			snprintfrr(buf, sizeof(buf), "%pI4",
				   (struct in_addr *)&peer);
		else
			snprintfrr(buf, sizeof(buf), "%pI6", &peer);
		json_object_string_add(jo_group, "peer", buf);
		json_object_string_add(jo_group, "vrf", vrfname);
		if (ifname)
			json_object_string_add(jo_group, "interface", ifname);

		jo_nharray = json_object_new_array();
		TAILQ_FOREACH (sgm, &srg->srg_sgmlist, sgm_entry) {
			sn = sgm->sgm_sn;
			static_bfd_show_nexthop_json(vty, jo_nharray, sn);
		}

		json_object_object_add(jo_group, "routes", jo_nharray);
		json_object_array_add(jo, jo_group);
	}
}

static void static_bfd_show_path_json(struct vty *vty, struct json_object *jo,
				      struct route_table *rt)
{
	struct static_route_info *si;
	struct static_nexthop *sn;
	struct static_path *sp;
	struct route_node *rn;

	for (rn = route_top(rt); rn; rn = srcdest_route_next(rn)) {
		si = static_route_info_from_rnode(rn);
		if (si == NULL)
			continue;

		frr_each (static_path_list, &si->path_list, sp) {
			frr_each (static_nexthop_list, &sp->nexthop_list, sn) {
				/* Skip non configured BFD sessions. */
				if (sn->bsp == NULL)
					continue;

				static_bfd_show_nexthop_json(vty, jo, sn);
			}
		}
	}
}

static void static_bfd_show_json(struct vty *vty)
{
	struct json_object *jo, *jo_path, *jo_group, *jo_afi_safi;
	struct static_vrf *svrf;
	struct route_table *rt;
	struct vrf *vrf;

	jo = json_object_new_object();
	jo_path = json_object_new_object();
	jo_group = json_object_new_array();

	json_object_object_add(jo, "route-group", jo_group);
	static_bfd_show_group_json(vty, jo_group);

	json_object_object_add(jo, "path-list", jo_path);
	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		svrf = vrf->info;

		jo_afi_safi = json_object_new_array();
		json_object_object_add(jo_path, "ipv4-unicast", jo_afi_safi);
		rt = svrf->stable[AFI_IP][SAFI_UNICAST];
		if (rt)
			static_bfd_show_path_json(vty, jo_afi_safi, rt);

		jo_afi_safi = json_object_new_array();
		json_object_object_add(jo_path, "ipv4-multicast", jo_afi_safi);
		rt = svrf->stable[AFI_IP][SAFI_MULTICAST];
		if (rt)
			static_bfd_show_path_json(vty, jo_afi_safi, rt);

		jo_afi_safi = json_object_new_array();
		json_object_object_add(jo_path, "ipv6-unicast", jo_afi_safi);
		rt = svrf->stable[AFI_IP6][SAFI_UNICAST];
		if (rt)
			static_bfd_show_path_json(vty, jo_afi_safi, rt);
	}

	vty_out(vty, "%s\n", json_object_to_json_string_ext(jo, 0));
	json_object_free(jo);
}

static void static_bfd_show_nexthop(struct vty *vty,
				    const struct static_nexthop *sn)
{
	char buf[SRCDEST2STR_BUFFER];

	vty_out(vty, "        %s",
		srcdest_rnode2str(sn->rn, buf, sizeof(buf)));

	if (sn->bsp == NULL) {
		vty_out(vty, "\n");
		return;
	}

	if (sn->type == STATIC_IPV4_GATEWAY
	    || sn->type == STATIC_IPV4_GATEWAY_IFNAME)
		vty_out(vty, " peer %pI4", &sn->addr.ipv4);
	else if (sn->type == STATIC_IPV6_GATEWAY
		 || sn->type == STATIC_IPV6_GATEWAY_IFNAME)
		vty_out(vty, " peer %pI6", &sn->addr.ipv6);
	else
		vty_out(vty, " peer unknown");

	vty_out(vty, " (status: %s)\n",
		sn->path_down ? "uninstalled" : "installed");
}

static void static_bfd_show_group(struct vty *vty)
{
	struct static_group_member *sgm;
	struct static_route_group *srg;
	struct static_nexthop *sn;
	enum bfd_session_state bss;
	const char *vrfname;
	const char *ifname;
	int family;
	uint8_t min_ttl;
	struct in6_addr local, peer;

	TAILQ_FOREACH (srg, &sbglobal.sbg_srglist, srg_entry) {
		/* Skip groups without BFD configuration. */
		if (srg->srg_bsp == NULL)
			continue;

		bss = bfd_sess_status(srg->srg_bsp);
		bfd_sess_addresses(srg->srg_bsp, &family, &local,
					     &peer);
		ifname = bfd_sess_interface(srg->srg_bsp);
		vrfname = bfd_sess_vrf(srg->srg_bsp);
		min_ttl = bfd_sess_minimum_ttl(srg->srg_bsp);

		vty_out(vty, "    %s", srg->srg_name);
		if (strcmp(vrfname, VRF_DEFAULT_NAME))
			vty_out(vty, " VRF %s", vrfname);
		if (ifname)
			vty_out(vty, " interface %s", ifname);

		if (family == AF_INET)
			vty_out(vty, " peer %pI4", (struct in_addr *)&peer);
		else
			vty_out(vty, " peer %pI6", (struct in6_addr *)&peer);

		if (min_ttl != BFD_SINGLE_HOP_TTL) {
			if (family == AF_INET)
				vty_out(vty, " multi-hop source %pI4",
					(struct in_addr *)&local);
			else
				vty_out(vty, " multi-hop source %pI6", &local);
		}

		vty_out(vty, " (status: %s):\n",
			bss == BSS_UP ? "installed" : "uninstalled");

		TAILQ_FOREACH (sgm, &srg->srg_sgmlist, sgm_entry) {
			sn = sgm->sgm_sn;
			static_bfd_show_nexthop(vty, sn);
		}
	}
}

static void static_bfd_show_path(struct vty *vty, struct route_table *rt)
{
	struct static_route_info *si;
	struct static_nexthop *sn;
	struct static_path *sp;
	struct route_node *rn;

	for (rn = route_top(rt); rn; rn = srcdest_route_next(rn)) {
		si = static_route_info_from_rnode(rn);
		if (si == NULL)
			continue;

		frr_each (static_path_list, &si->path_list, sp) {
			frr_each (static_nexthop_list, &sp->nexthop_list, sn) {
				/* Skip non configured BFD sessions. */
				if (sn->bsp == NULL)
					continue;

				static_bfd_show_nexthop(vty, sn);
			}
		}
	}
}

void static_bfd_show(struct vty *vty, bool isjson)
{
	struct static_vrf *svrf;
	struct route_table *rt;
	struct vrf *vrf;

	if (isjson) {
		static_bfd_show_json(vty);
		return;
	}

	vty_out(vty, "Showing BFD monitored static routes:\n");

	/* Route groups. */
	vty_out(vty, "\n  Route groups:\n");
	static_bfd_show_group(vty);

	/* Individual next hops. */
	vty_out(vty, "\n  Next hops:\n");
	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		svrf = vrf->info;

		vty_out(vty, "    VRF %s IPv4 Unicast:\n", vrf->name);
		rt = svrf->stable[AFI_IP][SAFI_UNICAST];
		if (rt)
			static_bfd_show_path(vty, rt);

		vty_out(vty, "\n    VRF %s IPv4 Multicast:\n", vrf->name);
		rt = svrf->stable[AFI_IP][SAFI_MULTICAST];
		if (rt)
			static_bfd_show_path(vty, rt);

		vty_out(vty, "\n    VRF %s IPv6 Unicast:\n", vrf->name);
		rt = svrf->stable[AFI_IP6][SAFI_UNICAST];
		if (rt)
			static_bfd_show_path(vty, rt);
	}

	vty_out(vty, "\n");
}
