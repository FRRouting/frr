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
void static_bfd_initialize(struct zclient *zc, struct thread_master *tm)
{
	/* Initialize list head. */
	TAILQ_INIT(&sbglobal.sbg_srglist);

	/* Initialize BFD integration library. */
	bfd_protocol_integration_init(zc, tm);
}
