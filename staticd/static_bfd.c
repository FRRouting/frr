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
		sn->path_down = true;
		static_zebra_route_add(sn->pn, true);
		break;
	case BSS_UP:
		/* Peer is back up, add this next hop. */
		sn->path_down = false;
		static_zebra_route_add(sn->pn, true);
		break;
	}
}

static void static_next_hop_bfd_updatecb(
	__attribute__((unused)) struct bfd_session_params *bsp,
	const struct bfd_session_status *bss, void *arg)
{
	static_next_hop_bfd_change(arg, bss);
}

static int static_bfd_family_from_sn(struct static_nexthop *sn)
{
        if (sn->type == STATIC_IPV4_GATEWAY
            || sn->type == STATIC_IPV4_GATEWAY_IFNAME)
                return AF_INET;
        if (sn->type == STATIC_IPV6_GATEWAY
            || sn->type == STATIC_IPV6_GATEWAY_IFNAME)
                return AF_INET6;
        return AF_UNSPEC;
}

void static_next_hop_bfd_monitor_create(struct static_nexthop *sn,
					const struct lyd_node *dnode)
{
	bool use_interface;

	switch (sn->type) {
	case STATIC_IPV4_GATEWAY_IFNAME:
	case STATIC_IPV6_GATEWAY_IFNAME:
		use_interface = true;
		break;
	case STATIC_IPV4_GATEWAY:
	case STATIC_IPV6_GATEWAY:
		use_interface = false;
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

	if (sn->nh_vrf_id != VRF_DEFAULT)
		bfd_sess_set_vrf(sn->bsp, sn->nh_vrf_id);

	bfd_sess_set_interface(sn->bsp, use_interface ? sn->ifname : NULL);

	static_next_hop_bfd_profile(sn, dnode, false);
	static_next_hop_bfd_hop(sn, dnode, false);
	static_next_hop_bfd_source(sn, dnode, false);
	bfd_sess_install(sn->bsp);
}

void static_next_hop_bfd_monitor_destroy(struct static_nexthop *sn)
{
	bfd_sess_free(&sn->bsp);

	/* Reset path status. */
	sn->path_down = false;
}

void static_next_hop_bfd_hop(struct static_nexthop *sn,
		const struct lyd_node *dnode, bool upper_node)
{
	bool onlink;
	bool mhop;

	if (sn->bsp == NULL)
		return;

	if (upper_node) {
		onlink = yang_dnode_exists(dnode, "../../onlink")
			 && yang_dnode_get_bool(dnode, "../../onlink");
		mhop = yang_dnode_exists(dnode, "../multi-hop")
			&& yang_dnode_get_bool(dnode, "../multi-hop");

	} else {
		onlink = yang_dnode_exists(dnode, "../onlink")
			 && yang_dnode_get_bool(dnode, "../onlink");
		mhop = yang_dnode_exists(dnode, "./multi-hop")
			&& yang_dnode_get_bool(dnode, "./multi-hop");
	}

	bfd_sess_set_hop_count(sn->bsp, (!onlink && mhop) ?
			BFD_MULTI_HOP_MAX_HOP_COUNT : BFD_SINGLE_HOP_COUNT);
	if (upper_node)
		bfd_sess_install(sn->bsp);
}

void static_next_hop_bfd_profile(struct static_nexthop *sn,
		const struct lyd_node *dnode, bool upper_node)
{
	const char *profile_name;
	char profile_str[15];

	if (sn->bsp == NULL)
		return;

	if (upper_node)
		snprintf(profile_str, sizeof(profile_str), "../profile");
	else
		snprintf(profile_str, sizeof(profile_str), "./profile");

	if (yang_dnode_exists(dnode, profile_str))
		profile_name = yang_dnode_get_string(dnode, profile_str);
	else
		profile_name = NULL;

	bfd_sess_set_profile(sn->bsp, profile_name);

	if (upper_node)
		bfd_sess_install(sn->bsp);
}

void static_next_hop_bfd_source(struct static_nexthop *sn,
				const struct lyd_node *dnode, bool upper_node)
{
	int family;
	struct ipaddr ia_src = {};
	struct in6_addr ia_srcp = {};
	char src_str[15];
	bool source;

	if (sn->bsp == NULL)
		return;

	if (upper_node)
		snprintf(src_str, sizeof(src_str), "../source");
	else
		snprintf(src_str, sizeof(src_str), "./source");

	family = static_bfd_family_from_sn(sn);
	if (family == AF_UNSPEC)
		return;

	source = yang_dnode_exists(dnode, src_str);
	if (source) {
		yang_dnode_get_ip(&ia_src, dnode, src_str, NULL);
		memcpy(&ia_srcp, &(ia_src.ip), sizeof(struct in6_addr));
	}

	if (family == AF_INET)
		bfd_sess_set_ipv4_addrs(sn->bsp,
				source ? (struct in_addr *)&ia_srcp : NULL, &sn->addr.ipv4);
	else
		bfd_sess_set_ipv6_addrs(sn->bsp,
				source ? &ia_srcp : NULL, &sn->addr.ipv6);

	if (upper_node)
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
		static_zebra_route_add(sn->pn, true);
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

static struct static_route_group *static_route_group_lookup(const char *name,
		const char *vrfname)
{
	struct static_route_group *srg;

	TAILQ_FOREACH (srg, &sbglobal.sbg_srglist, srg_entry) {
		if (strcmp(srg->srg_name, name))
			continue;

		if (srg->vrfname[0] == '\0' &&
				strcmp(vrfname, VRF_DEFAULT_NAME))
			continue;
		if (strcmp(srg->vrfname, vrfname) &&
				strcmp(vrfname, VRF_DEFAULT_NAME))
			continue;

		return srg;
	}

	return NULL;
}

void static_group_fixup_vrf_ids(struct vrf *vrf, bool vrf_enabled)
{
	struct static_route_group *srg;
	vrf_id_t vrf_id;

	if (vrf_enabled)
		vrf_id = vrf->vrf_id;
	else
		vrf_id = VRF_UNKNOWN;

	TAILQ_FOREACH (srg, &sbglobal.sbg_srglist, srg_entry) {
		if (srg->vrfname[0] == '\0')
			continue;
		if (!srg->srg_bsp)
			continue;
		if (strcmp(vrf->name, srg->vrfname))
			continue;
		if (bfd_sess_set_vrf(srg->srg_bsp, vrf_id)
		    && vrf_enabled)
			bfd_sess_install(srg->srg_bsp);
	}
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

	srg = static_route_group_lookup(name, sn->nh_vrfname);
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
	srg = static_route_group_lookup(name, sn->nh_vrfname);
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

static void static_route_group_bfd_updatecb(
	__attribute__((unused)) struct bfd_session_params *bsp,
	const struct bfd_session_status *bss, void *arg)
{
	struct static_route_group *srg = arg;
	struct static_group_member *sgm;

	TAILQ_FOREACH (sgm, &srg->srg_sgmlist, sgm_entry)
		static_next_hop_bfd_change(sgm->sgm_sn, bss);
}

void static_route_group_bfd_create(struct static_route_group *srg,
				   const struct lyd_node *dnode)
{
	/* Reconfigure or allocate new memory. */
	if (srg->srg_bsp == NULL)
		srg->srg_bsp =
			bfd_sess_new(static_route_group_bfd_updatecb, srg);

	static_route_group_bfd_vrf(srg, dnode, false);
	static_route_group_bfd_addresses(srg, dnode, false);
	static_route_group_bfd_interface(srg, dnode, false);
	static_route_group_bfd_profile(srg, dnode, false);
	static_route_group_bfd_hop(srg, dnode, false);

	/* Install or update the session. */
	bfd_sess_install(srg->srg_bsp);
}


void static_route_group_bfd_destroy(struct static_route_group *srg)
{
	struct static_group_member *sgm;

	/* Free BFD session parameters if any. */
	bfd_sess_free(&srg->srg_bsp);

	/* Remove all members. */
	while ((sgm = TAILQ_FIRST(&srg->srg_sgmlist)) != NULL)
		static_group_member_free(&sgm);
}

void static_route_group_bfd_hop(struct static_route_group *srg,
		const struct lyd_node *dnode, bool upper_node)
{
	bool mhop;

	if (srg->srg_bsp == NULL)
		return;

	if (upper_node)
		mhop = yang_dnode_exists(dnode, "../multi-hop")
			&& yang_dnode_get_bool(dnode, "../multi-hop");
	else
		mhop = yang_dnode_exists(dnode, "./multi-hop")
			&& yang_dnode_get_bool(dnode, "./multi-hop");

	bfd_sess_set_hop_count(srg->srg_bsp, mhop ? BFD_MULTI_HOP_MAX_HOP_COUNT
			       : BFD_SINGLE_HOP_COUNT);

	if (upper_node)
		bfd_sess_install(srg->srg_bsp);
}

void static_route_group_bfd_profile(struct static_route_group *srg,
		const struct lyd_node *dnode, bool upper_node)
{
	const char *profile_name;
	char profile_str[15];

	if (srg->srg_bsp == NULL)
		return;

	if (upper_node)
		snprintf(profile_str, sizeof(profile_str), "../profile");
	else
		snprintf(profile_str, sizeof(profile_str), "./profile");

	if (yang_dnode_exists(dnode, profile_str))
		profile_name = yang_dnode_get_string(dnode, profile_str);
	else
		profile_name = NULL;

	bfd_sess_set_profile(srg->srg_bsp, profile_name);

	if (upper_node)
		bfd_sess_install(srg->srg_bsp);
}

void static_route_group_bfd_vrf(struct static_route_group *srg,
		const struct lyd_node *dnode, bool upper_node)
{
	const char *vrfname;
	struct vrf *vrf;
	bool ret;

	if (srg->srg_bsp == NULL)
		return;


	if (upper_node)
		vrfname = yang_dnode_get_string(dnode, "../vrf");
	else
		vrfname = yang_dnode_get_string(dnode, "./vrf");

	if (!vrfname || strcmp(vrfname, VRF_DEFAULT_NAME) == 0)
		srg->vrfname[0] = '\0';
	else
		snprintf(&srg->vrfname[0], sizeof(srg->vrfname), "%s", vrfname);

	vrf = vrf_lookup_by_name(vrfname);

	ret = bfd_sess_set_vrf(srg->srg_bsp, vrf ? vrf->vrf_id : VRF_UNKNOWN);

	if (upper_node && ret)
		bfd_sess_install(srg->srg_bsp);
}

void static_route_group_bfd_addresses(struct static_route_group *srg,
		const struct lyd_node *dnode, bool upper_node)
{
	struct ipaddr ia_src = {}, ia_dst = {};
	struct in6_addr ia_srcp = {};
	char src_str[15], dst_str[15];
	bool source;
	int family;

	if (srg->srg_bsp == NULL)
		return;
	if (upper_node) {
		snprintf(src_str, sizeof(src_str), "../source");
		snprintf(dst_str, sizeof(dst_str), "../peer");
	} else {
		snprintf(src_str, sizeof(src_str), "./source");
		snprintf(dst_str, sizeof(dst_str), "./peer");
	}

	yang_dnode_get_ip(&ia_dst, dnode, dst_str, NULL);

	family = ia_dst.ipa_type == IPADDR_V4 ? AF_INET : AF_INET6;

	source = yang_dnode_exists(dnode, src_str);
	if (source) {
		yang_dnode_get_ip(&ia_src, dnode, src_str, NULL);
		memcpy(&ia_srcp, &(ia_src.ip), sizeof(struct in6_addr));
	}

	if (family == AF_INET)
		bfd_sess_set_ipv4_addrs(srg->srg_bsp,
					source ? (struct in_addr *)&ia_srcp : NULL,
					(struct in_addr *)&ia_dst.ip);
	else
		bfd_sess_set_ipv6_addrs(srg->srg_bsp,
					source ? &ia_srcp : NULL,
					(struct in6_addr *)&ia_dst.ip);

	if (upper_node)
		bfd_sess_install(srg->srg_bsp);
}

void static_route_group_bfd_interface(struct static_route_group *srg,
		const struct lyd_node *dnode, bool upper_node)
{
	const char *ifname;
	char if_str[15];

	if (srg->srg_bsp == NULL)
		return;

	if (upper_node)
		snprintf(if_str, sizeof(if_str), "../interface");
	else
		snprintf(if_str, sizeof(if_str), "./interface");

	if (yang_dnode_exists(dnode, if_str))
		ifname = yang_dnode_get_string(dnode, if_str);
	else
		ifname = NULL;

	bfd_sess_set_interface(srg->srg_bsp, ifname);

	if (upper_node)
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
