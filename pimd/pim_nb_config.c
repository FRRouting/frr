// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2020 VmWare
 *                    Sarita Patra
 */

#include <zebra.h>

#include "pimd.h"
#include "pim_nb.h"
#include "lib/northbound_cli.h"
#include "lib/sockopt.h"
#include "pim_igmpv3.h"
#include "pim_neighbor.h"
#include "pim_nht.h"
#include "pim_pim.h"
#include "pim_mlag.h"
#include "pim_bfd.h"
#include "pim_msdp_socket.h"
#include "pimd/pim_rp.h"
#include "pim_static.h"
#include "pim_ssm.h"
#include "pim_dm.h"
#include "pim_ssmpingd.h"
#include "pim_vxlan.h"
#include "pim_util.h"
#include "log.h"
#include "lib_errors.h"
#include "pim_util.h"
#include "pim6_mld.h"
#include "pim_autorp.h"
#include "pim_igmp.h"
#include "pim_dm.h"

#if PIM_IPV == 6
#define pim6_msdp_err(funcname, argtype)                                       \
int funcname(struct argtype *args)                                             \
{                                                                              \
	snprintf(args->errmsg, args->errmsg_len,                               \
		 "Trying to configure MSDP in pim6d.  "                        \
		 "MSDP does not exist for IPv6.");                             \
	return NB_ERR_VALIDATION;                                              \
}                                                                              \
MACRO_REQUIRE_SEMICOLON()

#define pim6_autorp_err(funcname, argtype)                                                         \
	int funcname(struct argtype *args)                                                         \
	{                                                                                          \
		snprintf(args->errmsg, args->errmsg_len,                                           \
			 "Trying to configure AutoRP in pim6d.  "                                  \
			 "AutoRP does not exist for IPv6.");                                       \
		return NB_ERR_VALIDATION;                                                          \
	}                                                                                          \
	MACRO_REQUIRE_SEMICOLON()

#define yang_dnode_get_pimaddr yang_dnode_get_ipv6

#else /* PIM_IPV != 6 */
#define pim6_msdp_err(funcname, argtype)                                       \
MACRO_REQUIRE_SEMICOLON()

#define pim6_autorp_err(funcname, argtype) MACRO_REQUIRE_SEMICOLON()

#define yang_dnode_get_pimaddr yang_dnode_get_ipv4
#endif /* PIM_IPV != 6 */

/*
 * When PIM is disabled on interface, IGMPv3 local membership
 * information is not injected into PIM interface state.

 * The function pim_if_membership_refresh() fetches all IGMPv3 local
 * membership information into PIM. It is intented to be called
 * whenever PIM is enabled on the interface in order to collect missed
 * local membership information.
 */
static void pim_if_membership_refresh(struct interface *ifp)
{
	struct pim_interface *pim_ifp;
#if PIM_IPV == 4
	struct listnode *grpnode;
	struct gm_group *grp;
#else
	struct gm_if *gm_ifp;
	struct gm_sg *sg, *sg_start;
#endif

	pim_ifp = ifp->info;
	assert(pim_ifp);

	if (!pim_ifp->pim_enable)
		return;
	if (!pim_ifp->gm_enable)
		return;

#if PIM_IPV == 6
	gm_ifp = pim_ifp->mld;
	if (!gm_ifp)
		return;
#endif
	/*
	 * First clear off membership from all PIM (S,G) entries on the
	 * interface
	 */

	pim_ifchannel_membership_clear(ifp);

#if PIM_IPV == 4
	/*
	 * Then restore PIM (S,G) membership from all IGMPv3 (S,G) entries on
	 * the interface
	 */

	/* scan igmp groups */
	for (ALL_LIST_ELEMENTS_RO(pim_ifp->gm_group_list, grpnode, grp)) {
		struct listnode *srcnode;
		struct gm_source *src;

		/* scan group sources */
		for (ALL_LIST_ELEMENTS_RO(grp->group_source_list, srcnode,
					  src)) {

			if (IGMP_SOURCE_TEST_FORWARDING(src->source_flags)) {
				pim_sgaddr sg;

				memset(&sg, 0, sizeof(sg));
				sg.src = src->source_addr;
				sg.grp = grp->group_addr;
				pim_ifchannel_local_membership_add(
					ifp, &sg, false /*is_vxlan*/);
			}

		} /* scan group sources */
	}	 /* scan igmp groups */
#else
	sg_start = gm_sgs_first(gm_ifp->sgs);

	frr_each_from (gm_sgs, gm_ifp->sgs, sg, sg_start) {
		if (!in6_multicast_nofwd(&sg->sgaddr.grp)) {
			pim_ifchannel_local_membership_add(
				ifp, &sg->sgaddr, false /*is_vxlan*/);
		}
	}
#endif

	/*
	 * Finally delete every PIM (S,G) entry lacking all state info
	 */

	pim_ifchannel_delete_on_noinfo(ifp);
}

static int pim_cmd_interface_add(struct interface *ifp)
{
	struct pim_interface *pim_ifp = ifp->info;

	if (!pim_ifp)
		pim_ifp = pim_if_new(ifp, false, true, false, false);
	else
		pim_ifp->pim_enable = true;

	pim_if_addr_add_all(ifp);
	pim_nht_upstream_if_update(pim_ifp->pim, ifp);
	pim_if_membership_refresh(ifp);

	pim_if_create_pimreg(pim_ifp->pim);

#if PIM_IPV == 4
	pim_autorp_add_ifp(ifp);
#endif

	return 1;
}

static int interface_pim_use_src_cmd_worker(struct interface *ifp,
		pim_addr source_addr, char *errmsg, size_t errmsg_len)
{
	int result;
	int ret = NB_OK;

	result = pim_update_source_set(ifp, source_addr);

	switch (result) {
	case PIM_SUCCESS:
		break;
	case PIM_IFACE_NOT_FOUND:
		ret = NB_ERR;
		snprintf(errmsg, errmsg_len,
			 "Pim not enabled on this interface %s",
			 ifp->name);
			break;
	case PIM_UPDATE_SOURCE_DUP:
		ret = NB_ERR;
		snprintf(errmsg, errmsg_len, "Source already set");
		break;
	default:
		ret = NB_ERR;
		snprintf(errmsg, errmsg_len, "Source set failed");
	}

	return ret;
}

static int pim_cmd_spt_switchover(struct pim_instance *pim,
		enum pim_spt_switchover spt,
		const char *plist)
{
	pim->spt.switchover = spt;

	switch (pim->spt.switchover) {
	case PIM_SPT_IMMEDIATE:
		XFREE(MTYPE_PIM_PLIST_NAME, pim->spt.plist);

		pim_upstream_add_lhr_star_pimreg(pim);
		break;
	case PIM_SPT_INFINITY:
		pim_upstream_remove_lhr_star_pimreg(pim, plist);

		XFREE(MTYPE_PIM_PLIST_NAME, pim->spt.plist);

		if (plist)
			pim->spt.plist = XSTRDUP(MTYPE_PIM_PLIST_NAME, plist);
		break;
	}

	return NB_OK;
}

static int pim_dm_cmd_worker(struct pim_instance *pim, const char *plist, char *errmsg,
			     size_t errmsg_len)
{
	int result = pim_dm_range_set(pim, plist);

	if (result == PIM_DM_ERR_NONE)
		return NB_OK;

	switch (result) {
	case PIM_DM_ERR_DUP:
		snprintf(errmsg, errmsg_len, "Duplicate config");
		break;
	default:
		snprintf(errmsg, errmsg_len, "DM range config failed");
	}

	return NB_ERR;
}


static int pim_ssm_cmd_worker(struct pim_instance *pim, const char *plist,
		char *errmsg, size_t errmsg_len)
{
	int result = pim_ssm_range_set(pim, pim->vrf->vrf_id, plist);
	int ret = NB_ERR;

	if (result == PIM_SSM_ERR_NONE)
		return NB_OK;

	switch (result) {
	case PIM_SSM_ERR_NO_VRF:
		snprintf(errmsg, errmsg_len,
			 "VRF doesn't exist");
		break;
	case PIM_SSM_ERR_DUP:
		snprintf(errmsg, errmsg_len,
			 "duplicate config");
		break;
	default:
		snprintf(errmsg, errmsg_len,
			 "ssm range config failed");
	}

	return ret;
}

static int pim_rp_cmd_worker(struct pim_instance *pim, pim_addr rp_addr,
			     struct prefix group, const char *plist,
			     char *errmsg, size_t errmsg_len)
{
	int result;

	result = pim_rp_new(pim, rp_addr, group, plist, RP_SRC_STATIC);

	if (result == PIM_RP_NO_PATH) {
		snprintfrr(errmsg, errmsg_len,
			   "No Path to RP address specified: %pPA", &rp_addr);
		return NB_OK;
	}

	if (result == PIM_GROUP_OVERLAP) {
		snprintf(errmsg, errmsg_len,
			 "Group range specified cannot exact match another");
		return NB_ERR_INCONSISTENCY;
	}

	if (result == PIM_GROUP_PFXLIST_OVERLAP) {
		snprintf(errmsg, errmsg_len,
			 "This group is already covered by a RP prefix-list");
		return NB_ERR_INCONSISTENCY;
	}

	if (result == PIM_RP_PFXLIST_IN_USE) {
		snprintf(errmsg, errmsg_len,
			 "The same prefix-list cannot be applied to multiple RPs");
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int pim_no_rp_cmd_worker(struct pim_instance *pim, pim_addr rp_addr,
				struct prefix group, const char *plist,
				char *errmsg, size_t errmsg_len)
{
	char group_str[PREFIX2STR_BUFFER];
	int result;

	prefix2str(&group, group_str, sizeof(group_str));

	result = pim_rp_del(pim, rp_addr, group, plist, RP_SRC_STATIC);

	if (result == PIM_GROUP_BAD_ADDRESS) {
		snprintf(errmsg, errmsg_len,
			 "Bad group address specified: %s", group_str);
		return NB_ERR_INCONSISTENCY;
	}

	if (result == PIM_RP_BAD_ADDRESS) {
		snprintfrr(errmsg, errmsg_len, "Bad RP address specified: %pPA",
			   &rp_addr);
		return NB_ERR_INCONSISTENCY;
	}

	if (result == PIM_RP_NOT_FOUND) {
		snprintf(errmsg, errmsg_len,
			 "Unable to find specified RP");
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static bool is_pim_interface(const struct lyd_node *dnode)
{
	char if_xpath[XPATH_MAXLEN];
	const struct lyd_node *pim_enable_dnode;
	const struct lyd_node *igmp_enable_dnode;

	yang_dnode_get_path(dnode, if_xpath, sizeof(if_xpath));
	pim_enable_dnode =
		yang_dnode_getf(dnode,
				"%s/frr-pim:pim/address-family[address-family='%s']/pim-enable",
				if_xpath, FRR_PIM_AF_XPATH_VAL);
	igmp_enable_dnode = yang_dnode_getf(dnode,
			"%s/frr-gmp:gmp/address-family[address-family='%s']/enable",
			if_xpath, FRR_PIM_AF_XPATH_VAL);

	if (((pim_enable_dnode) &&
	     (yang_dnode_get_bool(pim_enable_dnode, "."))) ||
	     ((igmp_enable_dnode) &&
	     (yang_dnode_get_bool(igmp_enable_dnode, "."))))
		return true;

	return false;
}

static int pim_cmd_gm_start(struct interface *ifp)
{
	struct pim_interface *pim_ifp;
	uint8_t need_startup = 0;

	pim_ifp = ifp->info;

	if (!pim_ifp) {
		pim_ifp = pim_if_new(ifp, true, false, false, false);
		need_startup = 1;
	} else {
		if (!pim_ifp->gm_enable) {
			pim_ifp->gm_enable = true;
			need_startup = 1;
		}
	}
	pim_if_create_pimreg(pim_ifp->pim);

	/* 'ip igmp' executed multiple times, with need_startup
	 * avoid multiple if add all and membership refresh
	 */
	if (need_startup) {
		pim_if_addr_add_all(ifp);
		pim_if_membership_refresh(ifp);
	}

	return NB_OK;
}

/*
 * CLI reconfiguration affects the interface level (struct pim_interface).
 * This function propagates the reconfiguration to every active socket
 * for that interface.
 */
#if PIM_IPV == 4
static void igmp_sock_query_interval_reconfig(struct gm_sock *igmp)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;

	assert(igmp);
	assert(igmp->interface);
	assert(igmp->interface->info);

	ifp = igmp->interface;
	pim_ifp = ifp->info;

	if (PIM_DEBUG_GM_TRACE)
		zlog_debug("%s: Querier %pPAs on %s reconfig query_interval=%d",
			   __func__, &igmp->ifaddr, ifp->name,
			   pim_ifp->gm_default_query_interval);

	/*
	 * igmp_startup_mode_on() will reset QQI:

	 * igmp->querier_query_interval = pim_ifp->gm_default_query_interval;
	 */
	igmp_startup_mode_on(igmp);
}

static void igmp_sock_query_reschedule(struct gm_sock *igmp)
{
	if (igmp->mtrace_only)
		return;

	if (igmp->t_igmp_query_timer) {
		/* other querier present */
		assert(igmp->t_igmp_query_timer);
		assert(!igmp->t_other_querier_timer);

		pim_igmp_general_query_off(igmp);
		pim_igmp_general_query_on(igmp);

		assert(igmp->t_igmp_query_timer);
		assert(!igmp->t_other_querier_timer);
	} else {
		/* this is the querier */

		assert(!igmp->t_igmp_query_timer);
		assert(igmp->t_other_querier_timer);

		pim_igmp_other_querier_timer_off(igmp);
		pim_igmp_other_querier_timer_on(igmp);

		assert(!igmp->t_igmp_query_timer);
		assert(igmp->t_other_querier_timer);
	}
}
#endif /* PIM_IPV == 4 */

#if PIM_IPV == 4
static void change_query_interval(struct pim_interface *pim_ifp,
		int query_interval)
{
	struct listnode *sock_node;
	struct gm_sock *igmp;

	pim_ifp->gm_default_query_interval = query_interval;

	for (ALL_LIST_ELEMENTS_RO(pim_ifp->gm_socket_list, sock_node, igmp)) {
		igmp_sock_query_interval_reconfig(igmp);
		igmp_sock_query_reschedule(igmp);
	}
}
#endif

static void change_query_max_response_time(struct interface *ifp,
					   int query_max_response_time_dsec)
{
#if PIM_IPV == 4
	struct listnode *sock_node;
	struct gm_sock *igmp;
	struct listnode *grp_node;
	struct gm_group *grp;
#endif

	struct pim_interface *pim_ifp = ifp->info;

	if (pim_ifp->gm_query_max_response_time_dsec ==
	    query_max_response_time_dsec)
		return;

	pim_ifp->gm_query_max_response_time_dsec = query_max_response_time_dsec;

#if PIM_IPV == 6
	gm_ifp_update(ifp);
#else
	/*
	 * Below we modify socket/group/source timers in order to quickly
	 * reflect the change. Otherwise, those timers would args->eventually
	 * catch up.
	 */

	/* scan all sockets */
	for (ALL_LIST_ELEMENTS_RO(pim_ifp->gm_socket_list, sock_node, igmp)) {
		/* reschedule socket general query */
		igmp_sock_query_reschedule(igmp);
	}

	/* scan socket groups */
	for (ALL_LIST_ELEMENTS_RO(pim_ifp->gm_group_list, grp_node, grp)) {
		struct listnode *src_node;
		struct gm_source *src;

		/* reset group timers for groups in EXCLUDE mode */
		if (grp->group_filtermode_isexcl)
			igmp_group_reset_gmi(grp);

		/* scan group sources */
		for (ALL_LIST_ELEMENTS_RO(grp->group_source_list, src_node,
					  src)) {

			/* reset source timers for sources with running
			 * timers
			 */
			if (src->t_source_timer)
				igmp_source_reset_gmi(grp, src);
		}
	}
#endif /* PIM_IPV == 4 */
}

static void yang_addrsel(struct cand_addrsel *addrsel, const struct lyd_node *node)
{
	memset(addrsel->cfg_ifname, 0, sizeof(addrsel->cfg_ifname));
	addrsel->cfg_addr = PIMADDR_ANY;

	if (yang_dnode_exists(node, "if-any")) {
		addrsel->cfg_mode = CAND_ADDR_ANY;
	} else if (yang_dnode_exists(node, "address")) {
		addrsel->cfg_mode = CAND_ADDR_EXPLICIT;
		yang_dnode_get_pimaddr(&addrsel->cfg_addr, node, "address");
	} else if (yang_dnode_exists(node, "interface")) {
		addrsel->cfg_mode = CAND_ADDR_IFACE;
		strlcpy(addrsel->cfg_ifname, yang_dnode_get_string(node, "interface"),
			sizeof(addrsel->cfg_ifname));
	} else if (yang_dnode_exists(node, "if-loopback")) {
		addrsel->cfg_mode = CAND_ADDR_LO;
	}
	addrsel->cfg_enable = true;
}

int routing_control_plane_protocols_name_validate(
	struct nb_cb_create_args *args)
{
	const char *name;

	name = yang_dnode_get_string(args->dnode, "name");
	if (!strmatch(name, "pim")) {
		snprintf(args->errmsg, args->errmsg_len,
				"pim supports only one instance with name pimd");
		return NB_ERR_VALIDATION;
	}
	return NB_OK;
}

/*
 * XPath: /frr-pim:pim/address-family
 */
int pim_address_family_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int pim_address_family_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-pim:pim/address-family/packets
 */
int pim_address_family_packets_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		router->packet_process = yang_dnode_get_uint8(args->dnode,
				NULL);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-pim:pim/address-family/join-prune-interval
 */
int pim_address_family_join_prune_interval_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		router->t_periodic = yang_dnode_get_uint16(args->dnode, NULL);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-pim:pim/address-family/register-suppress-time
 */
int pim_address_family_register_suppress_time_modify(
	struct nb_cb_modify_args *args)
{
	uint16_t value;
	switch (args->event) {
	case NB_EV_VALIDATE:
		value = yang_dnode_get_uint16(args->dnode, NULL);
		/*
		 * As soon as this is non-constant it needs to be replaced with
		 * a yang_dnode_get to lookup the candidate value, *not* the
		 * operational value. Since the code has a field assigned and
		 * used for this value it should have YANG/CLI to set it too,
		 * otherwise just use the #define!
		 */
		/* RFC7761: 4.11.  Timer Values */
		if (value <= router->register_probe_time * 2) {
			snprintf(
				args->errmsg, args->errmsg_len,
				"Register suppress time (%u) must be more than "
				"twice the register probe time (%u).",
				value, router->register_probe_time);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		pim_update_suppress_timers(
			yang_dnode_get_uint16(args->dnode, NULL));
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/ecmp
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_ecmp_modify(
	struct nb_cb_modify_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		pim->ecmp_enable = yang_dnode_get_bool(args->dnode, NULL);
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/ecmp-rebalance
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_ecmp_rebalance_modify(
	struct nb_cb_modify_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		pim->ecmp_rebalance_enable =
			yang_dnode_get_bool(args->dnode, NULL);
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/keep-alive-timer
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_keep_alive_timer_modify(
	struct nb_cb_modify_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		pim->keep_alive_time = yang_dnode_get_uint16(args->dnode, NULL);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/rp-keep-alive-timer
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_keep_alive_timer_modify(
	struct nb_cb_modify_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		pim->rp_keep_alive_time = yang_dnode_get_uint16(args->dnode,
				NULL);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/send-v6-secondary
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_send_v6_secondary_modify(
	struct nb_cb_modify_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		pim->send_v6_secondary = yang_dnode_get_bool(args->dnode, NULL);
		break;
	}

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_send_v6_secondary_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/spt-switchover
 */
void routing_control_plane_protocols_control_plane_protocol_pim_address_family_spt_switchover_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;
	int spt_switch_action;
	const char *prefix_list = NULL;

	vrf = nb_running_get_entry(args->dnode, NULL, true);
	pim = vrf->info;
	spt_switch_action = yang_dnode_get_enum(args->dnode, "spt-action");

	switch (spt_switch_action) {
	case PIM_SPT_INFINITY:
		if (yang_dnode_exists(args->dnode,
				      "./spt-infinity-prefix-list"))
			prefix_list = yang_dnode_get_string(
				args->dnode, "./spt-infinity-prefix-list");

		pim_cmd_spt_switchover(pim, PIM_SPT_INFINITY,
					prefix_list);
		break;
	case PIM_SPT_IMMEDIATE:
		pim_cmd_spt_switchover(pim, PIM_SPT_IMMEDIATE, NULL);
	}
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/spt-switchover/spt-action
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_spt_switchover_spt_action_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/spt-switchover/spt-infinity-prefix-list
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_spt_switchover_spt_infinity_prefix_list_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_spt_switchover_spt_infinity_prefix_list_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}
/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/dm-prefix-list
 */

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_dm_prefix_list_modify(
	struct nb_cb_modify_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;
	const char *plist_name;
	int result;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		plist_name = yang_dnode_get_string(args->dnode, NULL);
		result = pim_dm_cmd_worker(pim, plist_name, args->errmsg, args->errmsg_len);

		if (result)
			return NB_ERR_INCONSISTENCY;

		break;
	}
	return NB_OK;
}
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_dm_prefix_list_destroy(
	struct nb_cb_destroy_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;
	int result;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		result = pim_dm_cmd_worker(pim, NULL, args->errmsg, args->errmsg_len);

		if (result)
			return NB_ERR_INCONSISTENCY;

		break;
	}
	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/ssm-prefix-list
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_ssm_prefix_list_modify(
	struct nb_cb_modify_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;
	const char *plist_name;
	int result;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		plist_name = yang_dnode_get_string(args->dnode, NULL);
		result = pim_ssm_cmd_worker(pim, plist_name, args->errmsg,
				args->errmsg_len);

		if (result)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_ssm_prefix_list_destroy(
	struct nb_cb_destroy_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;
	int result;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		result = pim_ssm_cmd_worker(pim, NULL, args->errmsg,
				args->errmsg_len);

		if (result)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/ssm-pingd-source-ip
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_ssm_pingd_source_ip_create(
	struct nb_cb_create_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;
	int result;
	pim_addr source_addr;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		yang_dnode_get_pimaddr(&source_addr, args->dnode, NULL);
		result = pim_ssmpingd_start(pim, source_addr);
		if (result) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "%% Failure starting ssmpingd for source %pPA: %d", &source_addr,
				   result);
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_ssm_pingd_source_ip_destroy(
	struct nb_cb_destroy_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;
	int result;
	pim_addr source_addr;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		yang_dnode_get_pimaddr(&source_addr, args->dnode, NULL);
		result = pim_ssmpingd_stop(pim, source_addr);
		if (result) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "%% Failure stopping ssmpingd for source %pPA: %d", &source_addr,
				   result);
			return NB_ERR_INCONSISTENCY;
		}

		break;
	}

	return NB_OK;
}

pim6_msdp_err(pim_msdp_hold_time_modify, nb_cb_modify_args);
pim6_msdp_err(pim_msdp_keep_alive_modify, nb_cb_modify_args);
pim6_msdp_err(pim_msdp_connection_retry_modify, nb_cb_modify_args);
pim6_msdp_err(pim_msdp_mesh_group_destroy, nb_cb_destroy_args);
pim6_msdp_err(pim_msdp_mesh_group_create, nb_cb_create_args);
pim6_msdp_err(pim_msdp_mesh_group_source_modify, nb_cb_modify_args);
pim6_msdp_err(pim_msdp_mesh_group_source_destroy, nb_cb_destroy_args);
pim6_msdp_err(pim_msdp_mesh_group_members_create, nb_cb_create_args);
pim6_msdp_err(pim_msdp_mesh_group_members_destroy, nb_cb_destroy_args);
pim6_msdp_err(pim_msdp_peer_sa_filter_in_modify, nb_cb_modify_args);
pim6_msdp_err(pim_msdp_peer_sa_filter_in_destroy, nb_cb_destroy_args);
pim6_msdp_err(pim_msdp_peer_sa_filter_out_modify, nb_cb_modify_args);
pim6_msdp_err(pim_msdp_peer_sa_filter_out_destroy, nb_cb_destroy_args);
pim6_msdp_err(pim_msdp_peer_sa_limit_modify, nb_cb_modify_args);
pim6_msdp_err(pim_msdp_peer_sa_limit_destroy, nb_cb_destroy_args);
pim6_msdp_err(pim_msdp_peer_as_modify, nb_cb_modify_args);
pim6_msdp_err(pim_msdp_peer_as_destroy, nb_cb_destroy_args);
pim6_msdp_err(
	routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_peer_source_ip_modify,
	nb_cb_modify_args);
pim6_msdp_err(
	routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_peer_destroy,
	nb_cb_destroy_args);
pim6_msdp_err(
	routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_peer_create,
	nb_cb_create_args);
pim6_msdp_err(pim_msdp_peer_authentication_type_modify, nb_cb_modify_args);
pim6_msdp_err(pim_msdp_peer_authentication_key_modify, nb_cb_modify_args);
pim6_msdp_err(pim_msdp_peer_authentication_key_destroy, nb_cb_destroy_args);
pim6_msdp_err(pim_msdp_log_neighbor_events_modify, nb_cb_modify_args);
pim6_msdp_err(pim_msdp_log_sa_events_modify, nb_cb_modify_args);
pim6_msdp_err(pim_msdp_originator_id_modify, nb_cb_modify_args);
pim6_msdp_err(pim_msdp_originator_id_destroy, nb_cb_destroy_args);
pim6_msdp_err(pim_msdp_shutdown_modify, nb_cb_modify_args);

#if PIM_IPV != 6
/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp/hold-time
 */
int pim_msdp_hold_time_modify(struct nb_cb_modify_args *args)
{
	struct pim_instance *pim;
	struct vrf *vrf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		pim->msdp.hold_time = yang_dnode_get_uint16(args->dnode, NULL);
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp/keep-alive
 */
int pim_msdp_keep_alive_modify(struct nb_cb_modify_args *args)
{
	struct pim_instance *pim;
	struct vrf *vrf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		pim->msdp.keep_alive = yang_dnode_get_uint16(args->dnode, NULL);
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp/connection-retry
 */
int pim_msdp_connection_retry_modify(struct nb_cb_modify_args *args)
{
	struct pim_instance *pim;
	struct vrf *vrf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		pim->msdp.connection_retry =
			yang_dnode_get_uint16(args->dnode, NULL);
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp/log-neighbor-events
 */
int pim_msdp_log_neighbor_events_modify(struct nb_cb_modify_args *args)
{
	struct pim_instance *pim;
	struct vrf *vrf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;

	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		if (yang_dnode_get_bool(args->dnode, NULL))
			SET_FLAG(pim->log_flags, PIM_MSDP_LOG_NEIGHBOR_EVENTS);
		else
			UNSET_FLAG(pim->log_flags, PIM_MSDP_LOG_NEIGHBOR_EVENTS);
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp/log-sa-events
 */
int pim_msdp_log_sa_events_modify(struct nb_cb_modify_args *args)
{
	struct pim_instance *pim;
	struct vrf *vrf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;

	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		if (yang_dnode_get_bool(args->dnode, NULL))
			SET_FLAG(pim->log_flags, PIM_MSDP_LOG_SA_EVENTS);
		else
			UNSET_FLAG(pim->log_flags, PIM_MSDP_LOG_SA_EVENTS);
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp/originator-id
 */
int pim_msdp_originator_id_modify(struct nb_cb_modify_args *args)
{
	struct pim_instance *pim;
	struct vrf *vrf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		yang_dnode_get_ipv4(&pim->msdp.originator_id, args->dnode, NULL);
		break;
	}

	return NB_OK;
}

int pim_msdp_originator_id_destroy(struct nb_cb_destroy_args *args)
{
	struct pim_instance *pim;
	struct vrf *vrf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		pim->msdp.originator_id.s_addr = INADDR_ANY;
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp/shutdown
 */
int pim_msdp_shutdown_modify(struct nb_cb_modify_args *args)
{
	struct pim_instance *pim;
	struct vrf *vrf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;

	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		pim_msdp_shutdown(pim, yang_dnode_get_bool(args->dnode, NULL));
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp-mesh-groups
 */
int pim_msdp_mesh_group_create(struct nb_cb_create_args *args)
{
	struct pim_msdp_mg *mg;
	struct vrf *vrf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		mg = pim_msdp_mg_new(vrf->info, yang_dnode_get_string(
							args->dnode, "./name"));
		nb_running_set_entry(args->dnode, mg);
		break;
	}

	return NB_OK;
}

int pim_msdp_mesh_group_destroy(struct nb_cb_destroy_args *args)
{
	struct pim_msdp_mg *mg;
	struct vrf *vrf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		mg = nb_running_unset_entry(args->dnode);
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim_msdp_mg_free(vrf->info, &mg);
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp-mesh-groups/source
 */
int pim_msdp_mesh_group_source_modify(struct nb_cb_modify_args *args)
{
	const struct lyd_node *vrf_dnode;
	struct pim_msdp_mg *mg;
	struct vrf *vrf;
	struct ipaddr ip;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		mg = nb_running_get_entry(args->dnode, NULL, true);
		vrf_dnode =
			yang_dnode_get_parent(args->dnode, "address-family");
		vrf = nb_running_get_entry(vrf_dnode, "../../", true);
		yang_dnode_get_ip(&ip, args->dnode, NULL);

		pim_msdp_mg_src_add(vrf->info, mg, &ip.ip._v4_addr);
		break;
	}
	return NB_OK;
}

int pim_msdp_mesh_group_source_destroy(struct nb_cb_destroy_args *args)
{
	const struct lyd_node *vrf_dnode;
	struct pim_msdp_mg *mg;
	struct vrf *vrf;
	struct in_addr addr;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		mg = nb_running_get_entry(args->dnode, NULL, true);
		vrf_dnode =
			yang_dnode_get_parent(args->dnode, "address-family");
		vrf = nb_running_get_entry(vrf_dnode, "../../", true);

		addr.s_addr = INADDR_ANY;
		pim_msdp_mg_src_add(vrf->info, mg, &addr);
		break;
	}
	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp-peer/authentication-type
 */
int pim_msdp_peer_authentication_type_modify(struct nb_cb_modify_args *args)
{
	struct pim_msdp_peer *mp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		mp = nb_running_get_entry(args->dnode, NULL, true);
		mp->auth_type = yang_dnode_get_enum(args->dnode, NULL);
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp-peer/authentication-key
 */
int pim_msdp_peer_authentication_key_modify(struct nb_cb_modify_args *args)
{
	struct pim_msdp_peer *mp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		if (strlen(yang_dnode_get_string(args->dnode, NULL)) >
		    TCP_MD5SIG_MAXKEYLEN) {
			snprintf(args->errmsg, args->errmsg_len,
				 "MD5 authentication key too long");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_APPLY:
		mp = nb_running_get_entry(args->dnode, NULL, true);
		XFREE(MTYPE_PIM_MSDP_AUTH_KEY, mp->auth_key);
		mp->auth_key = XSTRDUP(MTYPE_PIM_MSDP_AUTH_KEY,
				       yang_dnode_get_string(args->dnode, NULL));

		/* We must start listening the new authentication key now. */
		if (PIM_MSDP_PEER_IS_LISTENER(mp))
			pim_msdp_sock_auth_listen(mp);
		break;
	}

	return NB_OK;
}

int pim_msdp_peer_authentication_key_destroy(struct nb_cb_destroy_args *args)
{
	struct pim_msdp_peer *mp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		mp = nb_running_get_entry(args->dnode, NULL, true);
		XFREE(MTYPE_PIM_MSDP_AUTH_KEY, mp->auth_key);
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp-mesh-groups/members
 */
int pim_msdp_mesh_group_members_create(struct nb_cb_create_args *args)
{
	const struct lyd_node *vrf_dnode;
	struct pim_msdp_mg_mbr *mbr;
	struct pim_msdp_mg *mg;
	struct vrf *vrf;
	struct ipaddr ip;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		mg = nb_running_get_entry(args->dnode, NULL, true);
		vrf_dnode =
			yang_dnode_get_parent(args->dnode, "address-family");
		vrf = nb_running_get_entry(vrf_dnode, "../../", true);
		yang_dnode_get_ip(&ip, args->dnode, "address");

		mbr = pim_msdp_mg_mbr_add(vrf->info, mg, &ip.ip._v4_addr);
		nb_running_set_entry(args->dnode, mbr);
		break;
	}

	return NB_OK;
}

int pim_msdp_mesh_group_members_destroy(struct nb_cb_destroy_args *args)
{
	struct pim_msdp_mg_mbr *mbr;
	struct pim_msdp_mg *mg;
	const struct lyd_node *mg_dnode;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		mbr = nb_running_get_entry(args->dnode, NULL, true);
		mg_dnode =
			yang_dnode_get_parent(args->dnode, "msdp-mesh-groups");
		mg = nb_running_get_entry(mg_dnode, NULL, true);
		pim_msdp_mg_mbr_del(mg, mbr);
		nb_running_unset_entry(args->dnode);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp-peer
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_peer_create(
	struct nb_cb_create_args *args)
{
	struct pim_msdp_peer *mp;
	struct pim_instance *pim;
	struct vrf *vrf;
	struct ipaddr peer_ip;
	struct ipaddr source_ip;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		yang_dnode_get_ip(&peer_ip, args->dnode, "peer-ip");
		yang_dnode_get_ip(&source_ip, args->dnode, "source-ip");
		mp = pim_msdp_peer_add(pim, &peer_ip.ipaddr_v4,
				       &source_ip.ipaddr_v4, NULL);
		nb_running_set_entry(args->dnode, mp);
		break;
	}

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_peer_destroy(
	struct nb_cb_destroy_args *args)
{
	struct pim_msdp_peer *mp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		mp = nb_running_unset_entry(args->dnode);
		pim_msdp_peer_del(&mp);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp-peer/source-ip
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_peer_source_ip_modify(
	struct nb_cb_modify_args *args)
{
	struct pim_msdp_peer *mp;
	struct ipaddr source_ip;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		mp = nb_running_get_entry(args->dnode, NULL, true);
		yang_dnode_get_ip(&source_ip, args->dnode, NULL);
		pim_msdp_peer_change_source(mp, &source_ip.ipaddr_v4);
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp-peer/sa-filter-in
 */
int pim_msdp_peer_sa_filter_in_modify(struct nb_cb_modify_args *args)
{
	struct pim_msdp_peer *mp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		mp = nb_running_get_entry(args->dnode, NULL, true);
		XFREE(MTYPE_PIM_MSDP_FILTER_NAME, mp->acl_in);
		mp->acl_in = XSTRDUP(MTYPE_PIM_MSDP_FILTER_NAME,
				     yang_dnode_get_string(args->dnode, NULL));
		break;
	}

	return NB_OK;
}

int pim_msdp_peer_sa_filter_in_destroy(struct nb_cb_destroy_args *args)
{
	struct pim_msdp_peer *mp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		mp = nb_running_get_entry(args->dnode, NULL, true);
		XFREE(MTYPE_PIM_MSDP_FILTER_NAME, mp->acl_in);
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp-peer/sa-filter-out
 */
int pim_msdp_peer_sa_filter_out_modify(struct nb_cb_modify_args *args)
{
	struct pim_msdp_peer *mp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		mp = nb_running_get_entry(args->dnode, NULL, true);
		XFREE(MTYPE_PIM_MSDP_FILTER_NAME, mp->acl_out);
		mp->acl_out = XSTRDUP(MTYPE_PIM_MSDP_FILTER_NAME,
				      yang_dnode_get_string(args->dnode, NULL));
		break;
	}

	return NB_OK;
}

int pim_msdp_peer_sa_filter_out_destroy(struct nb_cb_destroy_args *args)
{
	struct pim_msdp_peer *mp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		mp = nb_running_get_entry(args->dnode, NULL, true);
		XFREE(MTYPE_PIM_MSDP_FILTER_NAME, mp->acl_out);
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp-peer/sa-limit
 */
int pim_msdp_peer_sa_limit_modify(struct nb_cb_modify_args *args)
{
	struct pim_msdp_peer *mp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		mp = nb_running_get_entry(args->dnode, NULL, true);
		mp->sa_limit = yang_dnode_get_uint32(args->dnode, NULL);
		break;
	}

	return NB_OK;
}

int pim_msdp_peer_sa_limit_destroy(struct nb_cb_destroy_args *args)
{
	struct pim_msdp_peer *mp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		mp = nb_running_get_entry(args->dnode, NULL, true);
		mp->sa_limit = 0;
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp-peer/as
 */
int pim_msdp_peer_as_modify(struct nb_cb_modify_args *args)
{
	struct pim_msdp_peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		peer = nb_running_get_entry(args->dnode, NULL, true);
		peer->asn = yang_dnode_get_uint32(args->dnode, NULL);
		break;
	}

	return NB_OK;
}

int pim_msdp_peer_as_destroy(struct nb_cb_destroy_args *args)
{
	struct pim_msdp_peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		peer = nb_running_get_entry(args->dnode, NULL, true);
		peer->asn = 0;
		break;
	}

	return NB_OK;
}
#endif /* PIM_IPV != 6 */

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/mlag
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_mlag_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_mlag_destroy(
	struct nb_cb_destroy_args *args)
{
	struct in_addr addr;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		addr.s_addr = 0;
		pim_vxlan_mlag_update(true/*mlag_enable*/,
				false/*peer_state*/, MLAG_ROLE_NONE,
				NULL/*peerlink*/, &addr);
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/mlag
 */
void routing_control_plane_protocols_control_plane_protocol_pim_address_family_mlag_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	const char *ifname;
	uint32_t role;
	bool peer_state;
	struct interface *ifp;
	struct ipaddr reg_addr;

	ifname = yang_dnode_get_string(args->dnode, "peerlink-rif");
	ifp = if_lookup_by_name(ifname, VRF_DEFAULT);
	if (!ifp) {
		snprintf(args->errmsg, args->errmsg_len,
			 "No such interface name %s", ifname);
		return;
	}
	role = yang_dnode_get_enum(args->dnode, "my-role");
	peer_state = yang_dnode_get_bool(args->dnode, "peer-state");
	yang_dnode_get_ip(&reg_addr, args->dnode, "reg-address");

	pim_vxlan_mlag_update(true, peer_state, role, ifp,
			&reg_addr.ip._v4_addr);
}


/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/mlag/peerlink-rif
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_mlag_peerlink_rif_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_mlag_peerlink_rif_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/mlag/reg-address
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_mlag_reg_address_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_mlag_reg_address_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/mlag/my-role
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_mlag_my_role_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/mlag/peer-state
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_mlag_peer_state_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/register-accept-list
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_register_accept_list_modify(
	struct nb_cb_modify_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;
	const char *plist;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		plist = yang_dnode_get_string(args->dnode, NULL);

		XFREE(MTYPE_PIM_PLIST_NAME, pim->register_plist);
		pim->register_plist = XSTRDUP(MTYPE_PIM_PLIST_NAME, plist);

		break;
	}

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_register_accept_list_destroy(
	struct nb_cb_destroy_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;

		XFREE(MTYPE_PIM_PLIST_NAME, pim->register_plist);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/mcast-rpf-lookup
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_mcast_rpf_lookup_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_mcast_rpf_lookup_destroy(
	struct nb_cb_destroy_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		pim_nht_change_rpf_mode(pim, yang_dnode_get_string(args->dnode, "group-list"),
					yang_dnode_get_string(args->dnode, "source-list"),
					MCAST_NO_CONFIG);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/mcast-rpf-lookup/mode
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_mcast_rpf_lookup_mode_modify(
	struct nb_cb_modify_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;
	enum pim_rpf_lookup_mode mode = MCAST_NO_CONFIG;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;

	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		mode = yang_dnode_get_enum(args->dnode, NULL);
		pim_nht_change_rpf_mode(pim, yang_dnode_get_string(args->dnode, "../group-list"),
					yang_dnode_get_string(args->dnode, "../source-list"), mode);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/address-family
 */
int lib_interface_pim_address_family_create(struct nb_cb_create_args *args)
{
	struct interface *ifp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_APPLY:
	case NB_EV_ABORT:
		break;
	case NB_EV_PREPARE:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		if (ifp->info)
			return NB_OK;

		pim_if_new(ifp, false, false, false, false);
		break;
	}

	return NB_OK;
}

int lib_interface_pim_address_family_destroy(struct nb_cb_destroy_args *args)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		pim_ifp = ifp->info;
		if (!pim_ifp)
			return NB_OK;

		pim_pim_interface_delete(ifp);
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/address-family/pim-enable
 */
int lib_interface_pim_address_family_pim_enable_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;
	int mcast_if_count;
	const struct lyd_node *if_dnode;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if_dnode = yang_dnode_get_parent(args->dnode, "interface");
		mcast_if_count =
			yang_get_list_elements_count(if_dnode);

		/* Limiting mcast interfaces to number of VIFs */
		if (mcast_if_count == MAXVIFS) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Max multicast interfaces(%d) reached.",
				 MAXVIFS);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);

		if (yang_dnode_get_bool(args->dnode, NULL)) {
			if (!pim_cmd_interface_add(ifp)) {
				snprintf(args->errmsg, args->errmsg_len,
					 "Could not enable PIM SM on interface %s",
					 ifp->name);
				return NB_ERR_INCONSISTENCY;
			}

			/* Trigger election in case it was never run before */
			pim_ifp = ifp->info;
			if (pim_addr_is_any(pim_ifp->pim_dr_addr))
				pim_if_dr_election(ifp);
		} else {
			pim_ifp = ifp->info;
			if (!pim_ifp)
				return NB_ERR_INCONSISTENCY;

			pim_pim_interface_delete(ifp);
		}
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-pim:pim/address-family/pim-passive-enable
 */
int lib_interface_pim_address_family_pim_passive_enable_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_ABORT:
	case NB_EV_PREPARE:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		pim_ifp = ifp->info;
		pim_ifp->pim_passive_enable = yang_dnode_get_bool(args->dnode, NULL);

		/* Trigger election in case it was never run before */
		if (pim_ifp->pim_passive_enable && pim_addr_is_any(pim_ifp->pim_dr_addr))
			pim_if_dr_election(ifp);
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-pim:pim/address-family/pim-mode
 */
int lib_interface_pim_address_family_pim_mode_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;
	enum pim_iface_mode mode;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_ABORT:
	case NB_EV_PREPARE:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		pim_ifp = ifp->info;
		mode = yang_dnode_get_enum(args->dnode, NULL);
		pim_dm_change_iif_mode(ifp, mode);
		pim_ifp->pim_mode = mode;
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/address-family/hello-interval
 */
int lib_interface_pim_address_family_hello_interval_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_ABORT:
	case NB_EV_PREPARE:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		pim_ifp = ifp->info;
		pim_ifp->pim_hello_period =
			yang_dnode_get_uint16(args->dnode, NULL);
		pim_ifp->pim_default_holdtime = -1;
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/address-family/hello-holdtime
 */
int lib_interface_pim_address_family_hello_holdtime_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_ABORT:
	case NB_EV_PREPARE:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		pim_ifp = ifp->info;
		pim_ifp->pim_default_holdtime =
			yang_dnode_get_uint16(args->dnode, NULL);
		break;
	}

	return NB_OK;

}

int lib_interface_pim_address_family_hello_holdtime_destroy(
	struct nb_cb_destroy_args *args)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_ABORT:
	case NB_EV_PREPARE:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		pim_ifp = ifp->info;
		pim_ifp->pim_default_holdtime = -1;
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/address-family/neighbor-filter-prefix-list
 */
int lib_interface_pim_address_family_nbr_plist_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;
	const char *plist;

	plist = yang_dnode_get_string(args->dnode, NULL);

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_ABORT:
	case NB_EV_PREPARE:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		pim_ifp = ifp->info;

		XFREE(MTYPE_PIM_PLIST_NAME, pim_ifp->nbr_plist);
		pim_ifp->nbr_plist = XSTRDUP(MTYPE_PIM_PLIST_NAME, plist);
		break;
	}

	return NB_OK;
}

int lib_interface_pim_address_family_nbr_plist_destroy(struct nb_cb_destroy_args *args)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_ABORT:
	case NB_EV_PREPARE:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		pim_ifp = ifp->info;
		XFREE(MTYPE_PIM_PLIST_NAME, pim_ifp->nbr_plist);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/address-family/bfd
 */
int lib_interface_pim_address_family_bfd_create(struct nb_cb_create_args *args)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		pim_ifp = ifp->info;
		pim_ifp->bfd_config.enabled = true;
		break;
	}

	return NB_OK;
}

int lib_interface_pim_address_family_bfd_destroy(
	struct nb_cb_destroy_args *args)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;
	const struct lyd_node *if_dnode;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if_dnode = yang_dnode_get_parent(args->dnode, "interface");
		if (!is_pim_interface(if_dnode)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Pim not enabled on this interface");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_ABORT:
	case NB_EV_PREPARE:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		pim_ifp = ifp->info;
		pim_ifp->bfd_config.enabled = false;
		pim_bfd_reg_dereg_all_nbr(ifp);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/address-family/bfd
 */
void lib_interface_pim_address_family_bfd_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	pim_ifp = ifp->info;

	if (!pim_ifp) {
		zlog_debug("Pim not enabled on this interface");
		return;
	}

	pim_ifp->bfd_config.detection_multiplier =
		yang_dnode_get_uint8(args->dnode, "detect_mult");
	pim_ifp->bfd_config.min_rx =
		yang_dnode_get_uint16(args->dnode, "min-rx-interval");
	pim_ifp->bfd_config.min_tx =
		yang_dnode_get_uint16(args->dnode, "min-tx-interval");

	pim_bfd_reg_dereg_all_nbr(ifp);
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/address-family/bfd/min-rx-interval
 */
int lib_interface_pim_address_family_bfd_min_rx_interval_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/address-family/bfd/min-tx-interval
 */
int lib_interface_pim_address_family_bfd_min_tx_interval_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/address-family/bfd/detect_mult
 */
int lib_interface_pim_address_family_bfd_detect_mult_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/address-family/bfd/profile
 */
int lib_interface_pim_address_family_bfd_profile_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		pim_ifp = ifp->info;
		XFREE(MTYPE_TMP, pim_ifp->bfd_config.profile);
		pim_ifp->bfd_config.profile = XSTRDUP(
			MTYPE_TMP, yang_dnode_get_string(args->dnode, NULL));
		break;
	}

	return NB_OK;
}

int lib_interface_pim_address_family_bfd_profile_destroy(
	struct nb_cb_destroy_args *args)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		pim_ifp = ifp->info;
		XFREE(MTYPE_TMP, pim_ifp->bfd_config.profile);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/address-family/bsm
 */
int lib_interface_pim_address_family_bsm_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		pim_ifp = ifp->info;
		if (!pim_ifp) {
			pim_ifp = pim_if_new(ifp, false, true, false, false);
			ifp->info = pim_ifp;
		}
		pim_ifp->bsm_enable = yang_dnode_get_bool(args->dnode, NULL);

		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/address-family/unicast-bsm
 */
int lib_interface_pim_address_family_unicast_bsm_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		pim_ifp = ifp->info;
		if (!pim_ifp) {
			pim_ifp = pim_if_new(ifp, false, true, false, false);
			ifp->info = pim_ifp;
		}
		pim_ifp->ucast_bsm_accept =
			yang_dnode_get_bool(args->dnode, NULL);

		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/address-family/active-active
 */
int lib_interface_pim_address_family_active_active_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		pim_ifp = ifp->info;
		if (yang_dnode_get_bool(args->dnode, NULL)) {
			if (PIM_DEBUG_MLAG)
				zlog_debug(
					"Configuring PIM active-active on Interface: %s",
					ifp->name);
			pim_if_configure_mlag_dualactive(pim_ifp);
		} else {
			if (PIM_DEBUG_MLAG)
				zlog_debug(
					"UnConfiguring PIM active-active on Interface: %s",
					ifp->name);
			pim_if_unconfigure_mlag_dualactive(pim_ifp);
		}

		break;
	}

	return NB_OK;

}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/address-family/dr-priority
 */
int lib_interface_pim_address_family_dr_priority_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;
	uint32_t old_dr_prio;
	const struct lyd_node *if_dnode;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if_dnode = yang_dnode_get_parent(args->dnode, "interface");
		if (!is_pim_interface(if_dnode)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Pim not enabled on this interface");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		pim_ifp = ifp->info;
		old_dr_prio = pim_ifp->pim_dr_priority;
		pim_ifp->pim_dr_priority = yang_dnode_get_uint32(args->dnode,
				NULL);

		if (old_dr_prio != pim_ifp->pim_dr_priority) {
			pim_if_dr_election(ifp);
			pim_hello_restart_now(ifp);
		}
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/address-family/use-source
 */
int lib_interface_pim_address_family_use_source_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	pim_addr source_addr;
	int result;
	const struct lyd_node *if_dnode;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if_dnode = yang_dnode_get_parent(args->dnode, "interface");
		if (!is_pim_interface(if_dnode)) {
			snprintf(args->errmsg, args->errmsg_len,
					"Pim not enabled on this interface");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_ABORT:
	case NB_EV_PREPARE:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
#if PIM_IPV == 4
		yang_dnode_get_ipv4(&source_addr, args->dnode, NULL);
#else
		yang_dnode_get_ipv6(&source_addr, args->dnode, NULL);
#endif

		result = interface_pim_use_src_cmd_worker(
				ifp, source_addr,
				args->errmsg, args->errmsg_len);

		if (result != PIM_SUCCESS)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

int lib_interface_pim_address_family_use_source_destroy(
	struct nb_cb_destroy_args *args)
{
	struct interface *ifp;
	int result;
	const struct lyd_node *if_dnode;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if_dnode = yang_dnode_get_parent(args->dnode, "interface");
		if (!is_pim_interface(if_dnode)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Pim not enabled on this interface");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_ABORT:
	case NB_EV_PREPARE:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);

		result = interface_pim_use_src_cmd_worker(ifp, PIMADDR_ANY,
				args->errmsg,
				args->errmsg_len);

		if (result != PIM_SUCCESS)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/address-family/multicast-boundary-oil
 */
int lib_interface_pim_address_family_multicast_boundary_oil_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;
	const struct lyd_node *if_dnode;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if_dnode = yang_dnode_get_parent(args->dnode, "interface");
		if (!is_pim_interface(if_dnode)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "%% Enable PIM and/or IGMP on this interface first");
			return NB_ERR_VALIDATION;
		}
		if (!prefix_list_lookup(AFI_IP, yang_dnode_get_string(args->dnode, NULL))) {
			snprintf(args->errmsg, args->errmsg_len,
				 "%% Specified prefix-list not found");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_ABORT:
	case NB_EV_PREPARE:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		pim_ifp = ifp->info;
		pim_ifp->boundary_oil_plist =
			prefix_list_lookup(AFI_IP, yang_dnode_get_string(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

int lib_interface_pim_address_family_multicast_boundary_oil_destroy(
	struct nb_cb_destroy_args *args)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;
	const struct lyd_node *if_dnode;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if_dnode = yang_dnode_get_parent(args->dnode, "interface");
		if (!is_pim_interface(if_dnode)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "%% Enable PIM and/or IGMP on this interface first");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_ABORT:
	case NB_EV_PREPARE:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		pim_ifp = ifp->info;
		pim_ifp->boundary_oil_plist = NULL;
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/address-family/multicast-boundary-acl
 */
int lib_interface_pim_address_family_multicast_boundary_acl_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;
	const struct lyd_node *if_dnode;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if_dnode = yang_dnode_get_parent(args->dnode, "interface");
		if (!is_pim_interface(if_dnode)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "%% Enable PIM and/or IGMP on this interface first");
			return NB_ERR_VALIDATION;
		}
		if (!access_list_lookup(AFI_IP, yang_dnode_get_string(args->dnode, NULL))) {
			snprintf(args->errmsg, args->errmsg_len,
				 "%% Specified access-list not found");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_ABORT:
	case NB_EV_PREPARE:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		pim_ifp = ifp->info;
		pim_ifp->boundary_acl =
			access_list_lookup(AFI_IP, yang_dnode_get_string(args->dnode, NULL));
		break;
	}

	return NB_OK;
}

int lib_interface_pim_address_family_multicast_boundary_acl_destroy(struct nb_cb_destroy_args *args)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;
	const struct lyd_node *if_dnode;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if_dnode = yang_dnode_get_parent(args->dnode, "interface");
		if (!is_pim_interface(if_dnode)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "%% Enable PIM and/or IGMP on this interface first");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_ABORT:
	case NB_EV_PREPARE:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		pim_ifp = ifp->info;
		pim_ifp->boundary_acl = NULL;
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/address-family/mroute
 */
int lib_interface_pim_address_family_mroute_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int lib_interface_pim_address_family_mroute_destroy(
	struct nb_cb_destroy_args *args)
{
	struct pim_instance *pim;
	struct pim_interface *pim_iifp;
	struct interface *iif;
	struct interface *oif;
	const char *oifname;
	pim_addr source_addr;
	pim_addr group_addr;
	const struct lyd_node *if_dnode;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if_dnode = yang_dnode_get_parent(args->dnode, "interface");
		if (!is_pim_interface(if_dnode)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "%% Enable PIM and/or IGMP on this interface first");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		iif = nb_running_get_entry(args->dnode, NULL, true);
		pim_iifp = iif->info;
		pim = pim_iifp->pim;

		oifname = yang_dnode_get_string(args->dnode, "oif");
		oif = if_lookup_by_name(oifname, pim->vrf->vrf_id);

		if (!oif) {
			snprintf(args->errmsg, args->errmsg_len,
					"No such interface name %s",
					oifname);
			return NB_ERR_INCONSISTENCY;
		}

		yang_dnode_get_pimaddr(&source_addr, args->dnode, "source-addr");
		yang_dnode_get_pimaddr(&group_addr, args->dnode, "group-addr");

		if (pim_static_del(pim, iif, oif, group_addr, source_addr)) {
			snprintf(args->errmsg, args->errmsg_len,
					"Failed to remove static mroute");
			return NB_ERR_INCONSISTENCY;
		}

		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/address-family/mroute/oif
 */
int lib_interface_pim_address_family_mroute_oif_modify(
	struct nb_cb_modify_args *args)
{
	struct pim_instance *pim;
	struct pim_interface *pim_iifp;
	struct interface *iif;
	struct interface *oif;
	const char *oifname;
	pim_addr source_addr;
	pim_addr group_addr;
	const struct lyd_node *if_dnode;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if_dnode = yang_dnode_get_parent(args->dnode, "interface");
		if (!is_pim_interface(if_dnode)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "%% Enable PIM and/or IGMP on this interface first");
			return NB_ERR_VALIDATION;
		}

#ifdef PIM_ENFORCE_LOOPFREE_MFC
		iif = nb_running_get_entry(args->dnode, NULL, false);
		if (!iif)
			return NB_OK;

		pim_iifp = iif->info;
		pim = pim_iifp->pim;

		oifname = yang_dnode_get_string(args->dnode, NULL);
		oif = if_lookup_by_name(oifname, pim->vrf->vrf_id);

		if (oif && (iif->ifindex == oif->ifindex)) {
			strlcpy(args->errmsg,
				"% IIF same as OIF and loopfree enforcement is enabled; rejecting",
				args->errmsg_len);
			return NB_ERR_VALIDATION;
		}
#endif
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		iif = nb_running_get_entry(args->dnode, NULL, true);
		pim_iifp = iif->info;
		pim = pim_iifp->pim;

		oifname = yang_dnode_get_string(args->dnode, NULL);
		oif = if_lookup_by_name(oifname, pim->vrf->vrf_id);
		if (!oif) {
			snprintf(args->errmsg, args->errmsg_len,
				 "No such interface name %s",
				 oifname);
			return NB_ERR_INCONSISTENCY;
		}

		yang_dnode_get_pimaddr(&source_addr, args->dnode, "../source-addr");
		yang_dnode_get_pimaddr(&group_addr, args->dnode, "../group-addr");

		if (pim_static_add(pim, iif, oif, group_addr, source_addr)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Failed to add static mroute");
			return NB_ERR_INCONSISTENCY;
		}

		break;
	}

	return NB_OK;
}

int lib_interface_pim_address_family_mroute_oif_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/static-rp/rp-list
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_static_rp_rp_list_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_static_rp_rp_list_destroy(
	struct nb_cb_destroy_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;
	struct prefix group;
	pim_addr rp_addr;
	const char *plist;
	int result = 0;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		yang_dnode_get_pimaddr(&rp_addr, args->dnode, "rp-address");

		if (yang_dnode_get(args->dnode, "group-list")) {
			yang_dnode_get_prefix(&group, args->dnode,
					      "./group-list");
			apply_mask(&group);
			result = pim_no_rp_cmd_worker(pim, rp_addr, group, NULL,
						      args->errmsg,
						      args->errmsg_len);
		}

		else if (yang_dnode_get(args->dnode, "prefix-list")) {
			plist = yang_dnode_get_string(args->dnode,
					"./prefix-list");
			pim_get_all_mcast_group(&group);
			result = pim_no_rp_cmd_worker(pim, rp_addr, group,
						      plist, args->errmsg,
						      args->errmsg_len);
		}

		if (result)
			return NB_ERR_INCONSISTENCY;
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/static-rp/rp-list/group-list
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_static_rp_rp_list_group_list_create(
	struct nb_cb_create_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;
	struct prefix group;
	pim_addr rp_addr;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		yang_dnode_get_pimaddr(&rp_addr, args->dnode, "../rp-address");
		yang_dnode_get_prefix(&group, args->dnode, NULL);
		apply_mask(&group);
		return pim_rp_cmd_worker(pim, rp_addr, group, NULL,
					 args->errmsg, args->errmsg_len);
	}

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_static_rp_rp_list_group_list_destroy(
	struct nb_cb_destroy_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;
	struct prefix group;
	pim_addr rp_addr;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		yang_dnode_get_pimaddr(&rp_addr, args->dnode, "../rp-address");
		yang_dnode_get_prefix(&group, args->dnode, NULL);
		apply_mask(&group);

		return pim_no_rp_cmd_worker(pim, rp_addr, group, NULL,
					    args->errmsg, args->errmsg_len);
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/static-rp/rp-list/prefix-list
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_static_rp_rp_list_prefix_list_modify(
	struct nb_cb_modify_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;
	struct prefix group;
	pim_addr rp_addr;
	const char *plist;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		plist = yang_dnode_get_string(args->dnode, NULL);
		yang_dnode_get_pimaddr(&rp_addr, args->dnode, "../rp-address");
		pim_get_all_mcast_group(&group);
		return pim_rp_cmd_worker(pim, rp_addr, group, plist,
					 args->errmsg, args->errmsg_len);
	}

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_static_rp_rp_list_prefix_list_destroy(
	struct nb_cb_destroy_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;
	struct prefix group;
	pim_addr rp_addr;
	const char *plist;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		yang_dnode_get_pimaddr(&rp_addr, args->dnode, "../rp-address");
		plist = yang_dnode_get_string(args->dnode, NULL);
		pim_get_all_mcast_group(&group);
		return pim_no_rp_cmd_worker(pim, rp_addr, group, plist,
					    args->errmsg, args->errmsg_len);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/embedded-rp/enable
 */
int pim_embedded_rp_enable_modify(struct nb_cb_modify_args *args)
{
#if PIM_IPV == 6
	struct vrf *vrf;
#endif /* PIM_IPV == 6 */

	switch (args->event) {
	case NB_EV_APPLY:
#if PIM_IPV == 6
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim_embedded_rp_enable(vrf->info, yang_dnode_get_bool(args->dnode, NULL));
		return NB_OK;
#else
		snprintf(args->errmsg, args->errmsg_len, "embedded RP is IPv6 only");
		return NB_ERR;
#endif /* PIM_IPV == 6 */

	case NB_EV_ABORT:
	case NB_EV_PREPARE:
	case NB_EV_VALIDATE:
	default:
		return NB_OK;
	}
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/embedded-rp/group-list
 */
int pim_embedded_rp_group_list_modify(struct nb_cb_modify_args *args)
{
#if PIM_IPV == 6
	struct vrf *vrf;
#endif /* PIM_IPV == 6 */

	switch (args->event) {
	case NB_EV_APPLY:
#if PIM_IPV == 6
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim_embedded_rp_set_group_list(vrf->info, yang_dnode_get_string(args->dnode, NULL));
		return NB_OK;
#else
		snprintf(args->errmsg, args->errmsg_len, "embedded RP is IPv6 only");
		return NB_ERR;
#endif /* PIM_IPV == 6 */

	case NB_EV_ABORT:
	case NB_EV_PREPARE:
	case NB_EV_VALIDATE:
	default:
		return NB_OK;
	}
}

int pim_embedded_rp_group_list_destroy(struct nb_cb_destroy_args *args)
{
#if PIM_IPV == 6
	struct vrf *vrf;
#endif /* PIM_IPV == 6 */

	switch (args->event) {
	case NB_EV_APPLY:
#if PIM_IPV == 6
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim_embedded_rp_set_group_list(vrf->info, NULL);
		return NB_OK;
#else
		snprintf(args->errmsg, args->errmsg_len, "embedded RP is IPv6 only");
		return NB_ERR;
#endif /* PIM_IPV == 6 */

	case NB_EV_ABORT:
	case NB_EV_PREPARE:
	case NB_EV_VALIDATE:
	default:
		return NB_OK;
	}
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/embedded-rp/maximum-rps
 */
int pim_embedded_rp_maximum_rps_modify(struct nb_cb_modify_args *args)
{
#if PIM_IPV == 6
	struct vrf *vrf;
#endif /* PIM_IPV == 6 */

	switch (args->event) {
	case NB_EV_APPLY:
#if PIM_IPV == 6
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim_embedded_rp_set_maximum_rps(vrf->info, yang_dnode_get_uint32(args->dnode, NULL));
		return NB_OK;
#else
		snprintf(args->errmsg, args->errmsg_len, "embedded RP is IPv6 only");
		return NB_ERR;
#endif /* PIM_IPV == 6 */

	case NB_EV_ABORT:
	case NB_EV_PREPARE:
	case NB_EV_VALIDATE:
	default:
		return NB_OK;
	}
}

pim6_autorp_err(
	routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_discovery_enabled_modify,
	nb_cb_modify_args);
pim6_autorp_err(
	routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_discovery_enabled_destroy,
	nb_cb_destroy_args);
pim6_autorp_err(
	routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_announce_scope_modify,
	nb_cb_modify_args);
pim6_autorp_err(
	routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_announce_scope_destroy,
	nb_cb_destroy_args);
pim6_autorp_err(
	routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_announce_interval_modify,
	nb_cb_modify_args);
pim6_autorp_err(
	routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_announce_interval_destroy,
	nb_cb_destroy_args);
pim6_autorp_err(
	routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_announce_holdtime_modify,
	nb_cb_modify_args);
pim6_autorp_err(
	routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_announce_holdtime_destroy,
	nb_cb_destroy_args);
pim6_autorp_err(
	routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_candidate_rp_list_create,
	nb_cb_create_args);
pim6_autorp_err(
	routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_candidate_rp_list_destroy,
	nb_cb_destroy_args);
pim6_autorp_err(
	routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_candidate_rp_list_group_modify,
	nb_cb_modify_args);
pim6_autorp_err(
	routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_candidate_rp_list_group_destroy,
	nb_cb_destroy_args);
pim6_autorp_err(
	routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_candidate_rp_list_prefix_list_modify,
	nb_cb_modify_args);
pim6_autorp_err(
	routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_candidate_rp_list_prefix_list_destroy,
	nb_cb_destroy_args);
pim6_autorp_err(
	routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_mapping_agent_send_rp_discovery_modify,
	nb_cb_modify_args);
pim6_autorp_err(
	routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_mapping_agent_discovery_scope_modify,
	nb_cb_modify_args);
pim6_autorp_err(
	routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_mapping_agent_discovery_interval_modify,
	nb_cb_modify_args);
pim6_autorp_err(
	routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_mapping_agent_discovery_holdtime_modify,
	nb_cb_modify_args);
pim6_autorp_err(
	routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_mapping_agent_addrsel_create,
	nb_cb_create_args);
pim6_autorp_err(
	routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_mapping_agent_addrsel_modify,
	nb_cb_modify_args);
pim6_autorp_err(
	routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_mapping_agent_addrsel_destroy,
	nb_cb_destroy_args);

#if PIM_IPV == 4
/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/auto-rp/discovery-enabled
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_discovery_enabled_modify(
	struct nb_cb_modify_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;
	bool enabled;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		enabled = yang_dnode_get_bool(args->dnode, NULL);
		if (enabled)
			pim_autorp_start_discovery(pim);
		else
			pim_autorp_stop_discovery(pim);
		break;
	}

	return NB_OK;
}
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_discovery_enabled_destroy(
	struct nb_cb_destroy_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		/* Run AutoRP discovery by default */
		pim_autorp_start_discovery(pim);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/auto-rp/announce-scope
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_announce_scope_modify(
	struct nb_cb_modify_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;
	uint8_t scope;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		scope = yang_dnode_get_uint8(args->dnode, NULL);
		pim_autorp_announce_scope(pim, scope);
		break;
	}

	return NB_OK;
}
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_announce_scope_destroy(
	struct nb_cb_destroy_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		pim_autorp_announce_scope(pim, 0);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/auto-rp/announce-interval
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_announce_interval_modify(
	struct nb_cb_modify_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;
	uint16_t interval;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		interval = yang_dnode_get_uint16(args->dnode, NULL);
		pim_autorp_announce_interval(pim, interval);
		break;
	}

	return NB_OK;
}
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_announce_interval_destroy(
	struct nb_cb_destroy_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		pim_autorp_announce_interval(pim, 0);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/auto-rp/announce-holdtime
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_announce_holdtime_modify(
	struct nb_cb_modify_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;
	uint16_t holdtime;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		holdtime = yang_dnode_get_uint16(args->dnode, NULL);
		pim_autorp_announce_holdtime(pim, holdtime);
		break;
	}

	return NB_OK;
}
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_announce_holdtime_destroy(
	struct nb_cb_destroy_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		/* 0 is a valid value, so -1 indicates deleting (go back to default) */
		pim_autorp_announce_holdtime(pim, -1);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/auto-rp/candidate-rp-list
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_candidate_rp_list_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_candidate_rp_list_destroy(
	struct nb_cb_destroy_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;
	pim_addr rp_addr;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		yang_dnode_get_pimaddr(&rp_addr, args->dnode, "rp-address");
		if (!pim_autorp_rm_candidate_rp(pim, rp_addr))
			return NB_ERR_INCONSISTENCY;
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/auto-rp/candidate-rp-list/group
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_candidate_rp_list_group_modify(
	struct nb_cb_modify_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;
	struct prefix group;
	pim_addr rp_addr;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		yang_dnode_get_pimaddr(&rp_addr, args->dnode, "../rp-address");
		yang_dnode_get_prefix(&group, args->dnode, NULL);
		apply_mask(&group);
		pim_autorp_add_candidate_rp_group(pim, rp_addr, group);
		break;
	}

	return NB_OK;
}
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_candidate_rp_list_group_destroy(
	struct nb_cb_destroy_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;
	struct prefix group;
	pim_addr rp_addr;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		yang_dnode_get_pimaddr(&rp_addr, args->dnode, "../rp-address");
		yang_dnode_get_prefix(&group, args->dnode, NULL);
		apply_mask(&group);
		if (!pim_autorp_rm_candidate_rp_group(pim, rp_addr, group))
			return NB_ERR_INCONSISTENCY;
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/auto-rp/candidate-rp-list/prefix-list
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_candidate_rp_list_prefix_list_modify(
	struct nb_cb_modify_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;
	pim_addr rp_addr;
	const char *plist;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		plist = yang_dnode_get_string(args->dnode, NULL);
		yang_dnode_get_pimaddr(&rp_addr, args->dnode, "../rp-address");
		pim_autorp_add_candidate_rp_plist(pim, rp_addr, plist);
		break;
	}

	return NB_OK;
}
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_candidate_rp_list_prefix_list_destroy(
	struct nb_cb_destroy_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;
	pim_addr rp_addr;
	const char *plist;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		yang_dnode_get_pimaddr(&rp_addr, args->dnode, "../rp-address");
		plist = yang_dnode_get_string(args->dnode, NULL);
		if (!pim_autorp_rm_candidate_rp_plist(pim, rp_addr, plist))
			return NB_ERR_INCONSISTENCY;
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/auto-rp/mapping-agent/send-rp-discovery
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_mapping_agent_send_rp_discovery_modify(
	struct nb_cb_modify_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		if (pim && pim->autorp) {
			pim->autorp->send_rp_discovery = yang_dnode_get_bool(args->dnode, NULL);
			pim_autorp_send_discovery_apply(pim->autorp);
		} else
			return NB_ERR_INCONSISTENCY;
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/auto-rp/mapping-agent/discovery-scope
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_mapping_agent_discovery_scope_modify(
	struct nb_cb_modify_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		if (pim && pim->autorp)
			pim->autorp->discovery_scope = yang_dnode_get_uint8(args->dnode, NULL);
		else
			return NB_ERR_INCONSISTENCY;
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/auto-rp/mapping-agent/discovery-interval
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_mapping_agent_discovery_interval_modify(
	struct nb_cb_modify_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		if (pim && pim->autorp)
			pim->autorp->discovery_interval = yang_dnode_get_uint16(args->dnode, NULL);
		else
			return NB_ERR_INCONSISTENCY;
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/auto-rp/mapping-agent/discovery-holdtime
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_mapping_agent_discovery_holdtime_modify(
	struct nb_cb_modify_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		if (pim && pim->autorp)
			pim->autorp->discovery_holdtime = yang_dnode_get_uint16(args->dnode, NULL);
		else
			return NB_ERR_INCONSISTENCY;
		break;
	}

	return NB_OK;
}

static int pim_autorp_mapping_agent_addrsel(struct pim_autorp *autorp,
					    const struct lyd_node *mapping_agent_node,
					    struct vrf *vrf)
{
	yang_addrsel(&autorp->mapping_agent_addrsel, mapping_agent_node);
	if (cand_addrsel_update(&autorp->mapping_agent_addrsel, vrf))
		pim_autorp_send_discovery_apply(autorp);
	return NB_OK;
}

/*
 * XPath:
 *  /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/auto-rp/mapping-agent/address
 *  /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/auto-rp/mapping-agent/interface
 *  /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/auto-rp/mapping-agent/if-loopback
 *  /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/auto-rp/mapping-agent/if-any
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_mapping_agent_addrsel_create(
	struct nb_cb_create_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;
	const struct lyd_node *mapping_agent_node;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		mapping_agent_node = yang_dnode_get_parent(args->dnode, "mapping-agent");
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		if (pim && pim->autorp)
			return pim_autorp_mapping_agent_addrsel(pim->autorp, mapping_agent_node,
								vrf);
		else
			return NB_ERR_INCONSISTENCY;
		break;
	}
	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_mapping_agent_addrsel_modify(
	struct nb_cb_modify_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;
	const struct lyd_node *mapping_agent_node;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		mapping_agent_node = yang_dnode_get_parent(args->dnode, "mapping-agent");
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		if (pim && pim->autorp)
			return pim_autorp_mapping_agent_addrsel(pim->autorp, mapping_agent_node,
								vrf);
		else
			return NB_ERR_INCONSISTENCY;
		break;
	}
	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_mapping_agent_addrsel_destroy(
	struct nb_cb_destroy_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		if (pim && pim->autorp)
			pim->autorp->mapping_agent_addrsel.cfg_enable = false;
		else
			return NB_ERR_INCONSISTENCY;
		break;
	}

	return NB_OK;
}
#endif /* PIM_IPV == 4  (for AutoRP)*/

static int candidate_bsr_addrsel(struct bsm_scope *scope,
				 const struct lyd_node *cand_bsr_node)
{
	yang_addrsel(&scope->bsr_addrsel, cand_bsr_node);
	pim_cand_bsr_apply(scope);
	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_candidate_bsr_create(
	struct nb_cb_create_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;
	struct bsm_scope *scope;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		scope = &pim->global_scope;

		scope->bsr_addrsel.cfg_enable = true;
		scope->cand_bsr_prio = yang_dnode_get_uint8(args->dnode,
							    "bsr-priority");

		candidate_bsr_addrsel(scope, args->dnode);
		break;
	}

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_candidate_bsr_destroy(
	struct nb_cb_destroy_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;
	struct bsm_scope *scope;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		scope = &pim->global_scope;

		scope->bsr_addrsel.cfg_enable = false;

		pim_cand_bsr_apply(scope);
		break;
	}

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_candidate_bsr_priority_modify(
	struct nb_cb_modify_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;
	struct bsm_scope *scope;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		scope = &pim->global_scope;

		scope->cand_bsr_prio = yang_dnode_get_uint8(args->dnode, NULL);

		/* FIXME: force prio update */
		candidate_bsr_addrsel(scope, args->dnode);
		break;
	}

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_candidate_bsr_addrsel_create(
	struct nb_cb_create_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;
	struct bsm_scope *scope;
	const struct lyd_node *cand_bsr_node;

	cand_bsr_node = yang_dnode_get_parent(args->dnode, "candidate-bsr");

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		scope = &pim->global_scope;

		return candidate_bsr_addrsel(scope, cand_bsr_node);
	}
	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_candidate_bsr_addrsel_modify(
	struct nb_cb_modify_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;
	struct bsm_scope *scope;
	const struct lyd_node *cand_bsr_node;

	cand_bsr_node = yang_dnode_get_parent(args->dnode, "candidate-bsr");

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		scope = &pim->global_scope;

		return candidate_bsr_addrsel(scope, cand_bsr_node);
	}
	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_candidate_bsr_addrsel_destroy(
	struct nb_cb_destroy_args *args)
{
	/* nothing to do here, we'll get a CREATE for something else */
	return NB_OK;
}

static int candidate_rp_addrsel(struct bsm_scope *scope,
				const struct lyd_node *cand_rp_node)
{
	yang_addrsel(&scope->cand_rp_addrsel, cand_rp_node);
	pim_cand_rp_apply(scope);
	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_candidate_rp_create(
	struct nb_cb_create_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;
	struct bsm_scope *scope;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		scope = &pim->global_scope;

		scope->cand_rp_addrsel.cfg_enable = true;
		scope->cand_rp_prio = yang_dnode_get_uint8(args->dnode,
							   "rp-priority");
		scope->cand_rp_interval =
			yang_dnode_get_uint32(args->dnode,
					      "advertisement-interval");

		candidate_rp_addrsel(scope, args->dnode);
		break;
	}

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_candidate_rp_destroy(
	struct nb_cb_destroy_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;
	struct bsm_scope *scope;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		scope = &pim->global_scope;

		scope->cand_rp_addrsel.cfg_enable = false;

		pim_cand_rp_apply(scope);
		break;
	}

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_candidate_rp_priority_modify(
	struct nb_cb_modify_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;
	struct bsm_scope *scope;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		scope = &pim->global_scope;

		scope->cand_rp_prio = yang_dnode_get_uint8(args->dnode, NULL);

		pim_cand_rp_trigger(scope);
		break;
	}

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_candidate_rp_adv_interval_modify(
	struct nb_cb_modify_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;
	struct bsm_scope *scope;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		scope = &pim->global_scope;

		scope->cand_rp_interval = yang_dnode_get_uint32(args->dnode,
								NULL);

		pim_cand_rp_trigger(scope);
		break;
	}

	return NB_OK;
}

#if PIM_IPV == 4
#define yang_dnode_get_pim_p yang_dnode_get_ipv4p
#else
#define yang_dnode_get_pim_p yang_dnode_get_ipv6p
#endif

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_candidate_rp_group_list_create(
	struct nb_cb_create_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;
	struct bsm_scope *scope;
	prefix_pim p;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		scope = &pim->global_scope;

		yang_dnode_get_pim_p(&p, args->dnode, ".");
		pim_cand_rp_grp_add(scope, &p);
		break;
	}
	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_candidate_rp_group_list_destroy(
	struct nb_cb_destroy_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;
	struct bsm_scope *scope;
	prefix_pim p;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		scope = &pim->global_scope;

		yang_dnode_get_pim_p(&p, args->dnode, ".");
		pim_cand_rp_grp_del(scope, &p);
		break;
	}
	return NB_OK;
}

static int candidate_rp_addrsel_common(enum nb_event event,
				       const struct lyd_node *dnode)
{
	struct vrf *vrf;
	struct pim_instance *pim;
	struct bsm_scope *scope;

	dnode = lyd_parent(dnode);

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(dnode, NULL, true);
		pim = vrf->info;
		scope = &pim->global_scope;

		candidate_rp_addrsel(scope, dnode);
		break;
	}
	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_candidate_rp_addrsel_create(
	struct nb_cb_create_args *args)
{
	return candidate_rp_addrsel_common(args->event, args->dnode);
}

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_candidate_rp_addrsel_modify(
	struct nb_cb_modify_args *args)
{
	return candidate_rp_addrsel_common(args->event, args->dnode);
}

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_candidate_rp_addrsel_destroy(
	struct nb_cb_destroy_args *args)
{
	/* nothing to do here - we'll get a create or modify event too */
	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-gmp:gmp/address-family
 */
int lib_interface_gmp_address_family_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int lib_interface_gmp_address_family_destroy(struct nb_cb_destroy_args *args)
{
	struct interface *ifp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		pim_gm_interface_delete(ifp);
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-gmp:gmp/address-family/enable
 */
int lib_interface_gmp_address_family_enable_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	bool gm_enable;
	int mcast_if_count;
	const char *ifp_name;
	const struct lyd_node *if_dnode;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if_dnode = yang_dnode_get_parent(args->dnode, "interface");
		mcast_if_count =
			yang_get_list_elements_count(if_dnode);
		/* Limiting mcast interfaces to number of VIFs */
		if (mcast_if_count == MAXVIFS) {
			ifp_name = yang_dnode_get_string(if_dnode, "name");
			snprintf(
				args->errmsg, args->errmsg_len,
				"Max multicast interfaces(%d) Reached. Could not enable %s on interface %s",
				MAXVIFS, GM, ifp_name);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		gm_enable = yang_dnode_get_bool(args->dnode, NULL);

		if (gm_enable)
			return pim_cmd_gm_start(ifp);

		else
			pim_gm_interface_delete(ifp);
	}
	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-gmp:gmp/address-family/igmp-version
 */
int lib_interface_gmp_address_family_igmp_version_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;
	int igmp_version, old_version = 0;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		pim_ifp = ifp->info;

		if (!pim_ifp)
			return NB_ERR_INCONSISTENCY;

		igmp_version = yang_dnode_get_uint8(args->dnode, NULL);
		old_version = pim_ifp->igmp_version;
		pim_ifp->igmp_version = igmp_version;

		/* Current and new version is different refresh existing
		 * membership. Going from 3 -> 2 or 2 -> 3.
		 */
		if (old_version != igmp_version)
			pim_if_membership_refresh(ifp);

		break;
	}

	return NB_OK;
}

int lib_interface_gmp_address_family_igmp_version_destroy(
	struct nb_cb_destroy_args *args)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		pim_ifp = ifp->info;
		pim_ifp->igmp_version = IGMP_DEFAULT_VERSION;
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-gmp:gmp/address-family/mld-version
 */
int lib_interface_gmp_address_family_mld_version_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		pim_ifp = ifp->info;
		if (!pim_ifp)
			return NB_ERR_INCONSISTENCY;

		pim_ifp->mld_version = yang_dnode_get_uint8(args->dnode, NULL);
		gm_ifp_update(ifp);
		break;
	}

	return NB_OK;
}

int lib_interface_gmp_address_family_mld_version_destroy(
	struct nb_cb_destroy_args *args)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		pim_ifp = ifp->info;
		if (!pim_ifp)
			return NB_ERR_INCONSISTENCY;

		pim_ifp->mld_version = 2;
		gm_ifp_update(ifp);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-gmp:gmp/address-family/query-interval
 */
int lib_interface_gmp_address_family_query_interval_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	int query_interval;

#if PIM_IPV == 4
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		query_interval = yang_dnode_get_uint16(args->dnode, NULL);
		change_query_interval(ifp->info, query_interval);
	}
#else
	struct pim_interface *pim_ifp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		pim_ifp = ifp->info;
		if (!pim_ifp)
			return NB_ERR_INCONSISTENCY;

		query_interval = yang_dnode_get_uint16(args->dnode, NULL);
		pim_ifp->gm_default_query_interval = query_interval;
		gm_ifp_update(ifp);
	}
#endif
	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-gmp:gmp/address-family/query-max-response-time
 */
int lib_interface_gmp_address_family_query_max_response_time_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	int query_max_response_time_dsec;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		query_max_response_time_dsec =
			yang_dnode_get_uint16(args->dnode, NULL);
		change_query_max_response_time(ifp,
					       query_max_response_time_dsec);
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-gmp:gmp/address-family/last-member-query-interval
 */
int lib_interface_gmp_address_family_last_member_query_interval_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;
	int last_member_query_interval;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		pim_ifp = ifp->info;
		last_member_query_interval =
			yang_dnode_get_uint16(args->dnode, NULL);
		pim_ifp->gm_specific_query_max_response_time_dsec =
			last_member_query_interval;
#if PIM_IPV == 6
		gm_ifp_update(ifp);
#endif

		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-gmp:gmp/address-family/max-groups
 */
int lib_interface_gm_max_groups_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;
	const char *ifp_name;
	const struct lyd_node *if_dnode;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if_dnode = yang_dnode_get_parent(args->dnode, "interface");
		if (!is_pim_interface(if_dnode)) {
			ifp_name = yang_dnode_get_string(if_dnode, "name");
			snprintf(args->errmsg, args->errmsg_len,
				 "multicast not enabled on interface %s", ifp_name);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		pim_ifp = ifp->info;
		pim_ifp->gm_group_limit = yang_dnode_get_uint32(args->dnode, NULL);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-gmp:gmp/address-family/max-sources
 */
int lib_interface_gm_max_sources_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;
	const char *ifp_name;
	const struct lyd_node *if_dnode;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if_dnode = yang_dnode_get_parent(args->dnode, "interface");
		if (!is_pim_interface(if_dnode)) {
			ifp_name = yang_dnode_get_string(if_dnode, "name");
			snprintf(args->errmsg, args->errmsg_len,
				 "multicast not enabled on interface %s", ifp_name);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		pim_ifp = ifp->info;
		pim_ifp->gm_source_limit = yang_dnode_get_uint32(args->dnode, NULL);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-gmp:gmp/address-family/robustness-variable
 */
int lib_interface_gmp_address_family_robustness_variable_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;
	int last_member_query_count;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		pim_ifp = ifp->info;
		last_member_query_count =
			yang_dnode_get_uint8(args->dnode, NULL);
		pim_ifp->gm_last_member_query_count = last_member_query_count;
#if PIM_IPV == 6
		gm_ifp_update(ifp);
#endif
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-gmp:gmp/address-family/immediate-leave
 */
int lib_interface_gmp_immediate_leave_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		pim_ifp = ifp->info;
		pim_ifp->gmp_immediate_leave = yang_dnode_get_bool(args->dnode, NULL);
		break;
	}

	return NB_OK;
}

int lib_interface_gm_rmap_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;
	const char *rmap;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_ABORT:
	case NB_EV_PREPARE:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		pim_ifp = ifp->info;

		rmap = yang_dnode_get_string(args->dnode, NULL);
		pim_filter_ref_set_rmap(&pim_ifp->gmp_filter, rmap);
		break;
	}

	return NB_OK;
}

int lib_interface_gm_rmap_destroy(struct nb_cb_destroy_args *args)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_ABORT:
	case NB_EV_PREPARE:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		pim_ifp = ifp->info;
		pim_filter_ref_set_rmap(&pim_ifp->gmp_filter, NULL);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-gmp:gmp/address-family/require-router-alert
 */
int lib_interface_gmp_require_router_alert_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		pim_ifp = ifp->info;
		pim_ifp->gmp_require_ra = yang_dnode_get_bool(args->dnode, NULL);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-gmp:gmp/address-family/proxy
 */
int lib_interface_gmp_address_family_proxy_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		pim_ifp = ifp->info;
		if (pim_ifp) {
			pim_ifp->gm_proxy = yang_dnode_get_bool(args->dnode,
								NULL);

			if (pim_ifp->gm_proxy)
				pim_if_gm_proxy_init(pim_ifp->pim, ifp);
			else
				pim_if_gm_proxy_finis(pim_ifp->pim, ifp);
		}
	}
	return NB_OK;
}
/*
 * XPath: /frr-interface:lib/interface/frr-gmp:gmp/address-family/join-group
 */
int lib_interface_gmp_address_family_join_group_create(
	struct nb_cb_create_args *args)
{
	struct interface *ifp;
	pim_addr source_addr;
	pim_addr group_addr;
	int result;
	const char *ifp_name;
	const struct lyd_node *if_dnode;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if_dnode =  yang_dnode_get_parent(args->dnode, "interface");
		if (!is_pim_interface(if_dnode)) {
			ifp_name = yang_dnode_get_string(if_dnode, "name");
			snprintf(args->errmsg, args->errmsg_len,
				 "multicast not enabled on interface %s",
				 ifp_name);
			return NB_ERR_VALIDATION;
		}

		yang_dnode_get_pimaddr(&group_addr, args->dnode,
				       "./group-addr");
#if PIM_IPV == 4
		if (pim_is_group_224_0_0_0_24(group_addr)) {
			snprintf(
				args->errmsg, args->errmsg_len,
				"Groups within 224.0.0.0/24 are reserved and cannot be joined");
			return NB_ERR_VALIDATION;
		}
#else
		if (ipv6_mcast_reserved(&group_addr)) {
			snprintf(
				args->errmsg, args->errmsg_len,
				"Groups within ffx2::/16 are reserved and cannot be joined");
			return NB_ERR_VALIDATION;
		}
#endif
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		yang_dnode_get_pimaddr(&source_addr, args->dnode,
				       "./source-addr");
		yang_dnode_get_pimaddr(&group_addr, args->dnode,
				       "./group-addr");
		result = pim_if_gm_join_add(ifp, group_addr, source_addr,
					    GM_JOIN_STATIC);
		if (result) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Failure joining " GM " group");
			return NB_ERR_INCONSISTENCY;
		}
	}
	return NB_OK;
}

int lib_interface_gmp_address_family_join_group_destroy(
	struct nb_cb_destroy_args *args)
{
	struct interface *ifp;
	pim_addr source_addr;
	pim_addr group_addr;
	int result;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		yang_dnode_get_pimaddr(&source_addr, args->dnode,
				       "./source-addr");
		yang_dnode_get_pimaddr(&group_addr, args->dnode,
				       "./group-addr");
		result = pim_if_gm_join_del(ifp, group_addr, source_addr,
					    GM_JOIN_STATIC);

		if (result) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "%% Failure leaving " GM " group %pPAs %pPAs on interface %s: %d",
				   &source_addr, &group_addr, ifp->name, result);

			return NB_ERR_INCONSISTENCY;
		}

		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-gmp:gmp/address-family/static-group
 */
int lib_interface_gmp_address_family_static_group_create(
	struct nb_cb_create_args *args)
{
	struct interface *ifp;
	pim_addr source_addr;
	pim_addr group_addr;
	int result;
	const char *ifp_name;
	const struct lyd_node *if_dnode;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if_dnode = yang_dnode_get_parent(args->dnode, "interface");
		if (!is_pim_interface(if_dnode)) {
			ifp_name = yang_dnode_get_string(if_dnode, "name");
			snprintf(args->errmsg, args->errmsg_len,
				 "multicast not enabled on interface %s",
				 ifp_name);
			return NB_ERR_VALIDATION;
		}

		yang_dnode_get_pimaddr(&group_addr, args->dnode, "./group-addr");
#if PIM_IPV == 4
		if (pim_is_group_224_0_0_0_24(group_addr)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Groups within 224.0.0.0/24 are reserved and cannot be joined");
			return NB_ERR_VALIDATION;
		}
#else
		if (ipv6_mcast_reserved(&group_addr)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Groups within ffx2::/16 are reserved and cannot be joined");
			return NB_ERR_VALIDATION;
		}
#endif
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		yang_dnode_get_pimaddr(&source_addr, args->dnode,
				       "./source-addr");
		yang_dnode_get_pimaddr(&group_addr, args->dnode, "./group-addr");
		result = pim_if_static_group_add(ifp, group_addr, source_addr);
		if (result) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Failure adding static group");
			return NB_ERR_INCONSISTENCY;
		}
	}
	return NB_OK;
}

int lib_interface_gmp_address_family_static_group_destroy(
	struct nb_cb_destroy_args *args)
{
	struct interface *ifp;
	pim_addr source_addr;
	pim_addr group_addr;
	int result;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		yang_dnode_get_pimaddr(&source_addr, args->dnode,
				       "./source-addr");
		yang_dnode_get_pimaddr(&group_addr, args->dnode, "./group-addr");
		result = pim_if_static_group_del(ifp, group_addr, source_addr);

		if (result) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "%% Failure removing static group %pPAs %pPAs on interface %s: %d",
				   &source_addr, &group_addr, ifp->name, result);

			return NB_ERR_INCONSISTENCY;
		}

		break;
	}

	return NB_OK;
}
