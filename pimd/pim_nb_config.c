/*
 * Copyright (C) 2020 VmWare
 *                    Sarita Patra
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "pimd.h"
#include "pim_nb.h"
#include "lib/northbound_cli.h"
#include "pim_igmpv3.h"
#include "pim_pim.h"
#include "pim_mlag.h"
#include "pim_bfd.h"
#include "pim_static.h"
#include "pim_ssm.h"
#include "pim_ssmpingd.h"
#include "pim_vxlan.h"
#include "log.h"
#include "lib_errors.h"

static void pim_if_membership_clear(struct interface *ifp)
{
	struct pim_interface *pim_ifp;

	pim_ifp = ifp->info;
	assert(pim_ifp);

	if (PIM_IF_TEST_PIM(pim_ifp->options)
	    && PIM_IF_TEST_IGMP(pim_ifp->options)) {
		return;
	}

	pim_ifchannel_membership_clear(ifp);
}

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
	struct listnode *sock_node;
	struct igmp_sock *igmp;

	pim_ifp = ifp->info;
	assert(pim_ifp);

	if (!PIM_IF_TEST_PIM(pim_ifp->options))
		return;
	if (!PIM_IF_TEST_IGMP(pim_ifp->options))
		return;

	/*
	 * First clear off membership from all PIM (S,G) entries on the
	 * interface
	 */

	pim_ifchannel_membership_clear(ifp);

	/*
	 * Then restore PIM (S,G) membership from all IGMPv3 (S,G) entries on
	 * the interface
	 */

	/* scan igmp sockets */
	for (ALL_LIST_ELEMENTS_RO(pim_ifp->igmp_socket_list, sock_node, igmp)) {
		struct listnode *grpnode;
		struct igmp_group *grp;

		/* scan igmp groups */
		for (ALL_LIST_ELEMENTS_RO(igmp->igmp_group_list, grpnode,
					  grp)) {
			struct listnode *srcnode;
			struct igmp_source *src;

			/* scan group sources */
			for (ALL_LIST_ELEMENTS_RO(grp->group_source_list,
						  srcnode, src)) {

				if (IGMP_SOURCE_TEST_FORWARDING(
				    src->source_flags)) {
					struct prefix_sg sg;

					memset(&sg, 0,
					       sizeof(struct prefix_sg));
					sg.src = src->source_addr;
					sg.grp = grp->group_addr;
					pim_ifchannel_local_membership_add(
						ifp, &sg, false /*is_vxlan*/);
				}

			} /* scan group sources */
		}        /* scan igmp groups */
	}                 /* scan igmp sockets */

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
		PIM_IF_DO_PIM(pim_ifp->options);

	pim_if_addr_add_all(ifp);
	pim_if_membership_refresh(ifp);

	pim_if_create_pimreg(pim_ifp->pim);
	return 1;
}

static int pim_cmd_interface_delete(struct interface *ifp)
{
	struct pim_interface *pim_ifp = ifp->info;

	if (!pim_ifp)
		return 1;

	PIM_IF_DONT_PIM(pim_ifp->options);

	pim_if_membership_clear(ifp);

	/*
	 * pim_sock_delete() removes all neighbors from
	 * pim_ifp->pim_neighbor_list.
	 */
	pim_sock_delete(ifp, "pim unconfigured on interface");

	if (!PIM_IF_TEST_IGMP(pim_ifp->options)) {
		pim_if_addr_del_all(ifp);
		pim_if_delete(ifp);
	}

	return 1;
}

static int interface_pim_use_src_cmd_worker(struct interface *ifp,
		struct in_addr source_addr,
		char *errmsg, size_t errmsg_len)
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

static int pim_ssm_cmd_worker(struct pim_instance *pim, const char *plist,
		char *errmsg, size_t errmsg_len)
{
	int result = pim_ssm_range_set(pim, pim->vrf_id, plist);
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

static int ip_no_msdp_mesh_group_cmd_worker(struct pim_instance *pim,
		const char *mg,
		char *errmsg, size_t errmsg_len)
{
	enum pim_msdp_err result;

	result = pim_msdp_mg_del(pim, mg);

	switch (result) {
	case PIM_MSDP_ERR_NONE:
		break;
	case PIM_MSDP_ERR_NO_MG:
		snprintf(errmsg, errmsg_len,
			 "%% mesh-group does not exist");
		break;
	default:
		snprintf(errmsg, errmsg_len,
			 "mesh-group source del failed");
	}

	return result ? NB_ERR : NB_OK;
}

static int ip_msdp_mesh_group_member_cmd_worker(struct pim_instance *pim,
		const char *mg,
		struct in_addr mbr_ip,
		char *errmsg, size_t errmsg_len)
{
	enum pim_msdp_err result;
	int ret = NB_OK;

	result = pim_msdp_mg_mbr_add(pim, mg, mbr_ip);

	switch (result) {
	case PIM_MSDP_ERR_NONE:
		break;
	case PIM_MSDP_ERR_OOM:
		ret = NB_ERR;
		snprintf(errmsg, errmsg_len,
			 "%% Out of memory");
		break;
	case PIM_MSDP_ERR_MG_MBR_EXISTS:
		ret = NB_ERR;
		snprintf(errmsg, errmsg_len,
			 "%% mesh-group member exists");
		break;
	case PIM_MSDP_ERR_MAX_MESH_GROUPS:
		ret = NB_ERR;
		snprintf(errmsg, errmsg_len,
			 "%% Only one mesh-group allowed currently");
		break;
	default:
		ret = NB_ERR;
		snprintf(errmsg, errmsg_len,
			 "%% member add failed");
	}

	return ret;
}

static int ip_no_msdp_mesh_group_member_cmd_worker(struct pim_instance *pim,
		const char *mg,
		struct in_addr mbr_ip,
		char *errmsg,
		size_t errmsg_len)
{
	enum pim_msdp_err result;

	result = pim_msdp_mg_mbr_del(pim, mg, mbr_ip);

	switch (result) {
	case PIM_MSDP_ERR_NONE:
		break;
	case PIM_MSDP_ERR_NO_MG:
		snprintf(errmsg, errmsg_len,
			 "%% mesh-group does not exist");
		break;
	case PIM_MSDP_ERR_NO_MG_MBR:
		snprintf(errmsg, errmsg_len,
			 "%% mesh-group member does not exist");
		break;
	default:
		snprintf(errmsg, errmsg_len,
			 "%% mesh-group member del failed");
	}

	return result ? NB_ERR : NB_OK;
}

static int ip_msdp_mesh_group_source_cmd_worker(struct pim_instance *pim,
		const char *mg,
		struct in_addr src_ip,
		char *errmsg, size_t errmsg_len)
{
	enum pim_msdp_err result;

	result = pim_msdp_mg_src_add(pim, mg, src_ip);

	switch (result) {
	case PIM_MSDP_ERR_NONE:
		break;
	case PIM_MSDP_ERR_OOM:
		snprintf(errmsg, errmsg_len,
			 "%% Out of memory");
		break;
	case PIM_MSDP_ERR_MAX_MESH_GROUPS:
		snprintf(errmsg, errmsg_len,
			 "%% Only one mesh-group allowed currently");
		break;
	default:
		snprintf(errmsg, errmsg_len,
			 "%% source add failed");
	}

	return result ? NB_ERR : NB_OK;
}

static int ip_no_msdp_mesh_group_source_cmd_worker(struct pim_instance *pim,
		const char *mg,
		char *errmsg,
		size_t errmsg_len)
{
	enum pim_msdp_err result;

	result = pim_msdp_mg_src_del(pim, mg);

	switch (result) {
	case PIM_MSDP_ERR_NONE:
		break;
	case PIM_MSDP_ERR_NO_MG:
		snprintf(errmsg, errmsg_len,
			 "%% mesh-group does not exist");
		break;
	default:
		snprintf(errmsg, errmsg_len,
			 "%% mesh-group source del failed");
	}

	return result ? NB_ERR : NB_OK;
}

static int ip_msdp_peer_cmd_worker(struct pim_instance *pim,
		struct in_addr peer_addr,
		struct in_addr local_addr,
		char *errmsg, size_t errmsg_len)
{
	enum pim_msdp_err result;
	int ret = NB_OK;

	result = pim_msdp_peer_add(pim, peer_addr, local_addr, "default",
			NULL /* mp_p */);
	switch (result) {
	case PIM_MSDP_ERR_NONE:
		break;
	case PIM_MSDP_ERR_OOM:
		ret = NB_ERR;
		snprintf(errmsg, errmsg_len,
			 "%% Out of memory");
		break;
	case PIM_MSDP_ERR_PEER_EXISTS:
		ret = NB_ERR;
		snprintf(errmsg, errmsg_len,
			 "%% Peer exists");
		break;
	case PIM_MSDP_ERR_MAX_MESH_GROUPS:
		ret = NB_ERR;
		snprintf(errmsg, errmsg_len,
			 "%% Only one mesh-group allowed currently");
		break;
	default:
		ret = NB_ERR;
		snprintf(errmsg, errmsg_len,
			 "%% peer add failed");
	}

	return ret;
}

static int ip_no_msdp_peer_cmd_worker(struct pim_instance *pim,
		struct in_addr peer_addr,
		char *errmsg, size_t errmsg_len)
{
	enum pim_msdp_err result;

	result = pim_msdp_peer_del(pim, peer_addr);
	switch (result) {
	case PIM_MSDP_ERR_NONE:
		break;
	case PIM_MSDP_ERR_NO_PEER:
		snprintf(errmsg, errmsg_len,
			 "%% Peer does not exist");
		break;
	default:
		snprintf(errmsg, errmsg_len,
			 "%% peer del failed");
	}

	return result ? NB_ERR : NB_OK;
}

static int pim_rp_cmd_worker(struct pim_instance *pim,
		struct in_addr rp_addr,
		struct prefix group, const char *plist,
		char *errmsg, size_t errmsg_len)
{
	char rp_str[INET_ADDRSTRLEN];
	int result;

	inet_ntop(AF_INET, &rp_addr, rp_str, sizeof(rp_str));

	result = pim_rp_new(pim, rp_addr, group, plist, RP_SRC_STATIC);

	if (result == PIM_RP_NO_PATH) {
		snprintf(errmsg, errmsg_len,
			 "No Path to RP address specified: %s", rp_str);
		return NB_ERR_INCONSISTENCY;
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

static int pim_no_rp_cmd_worker(struct pim_instance *pim,
				struct in_addr rp_addr, struct prefix group,
				const char *plist,
				char *errmsg, size_t errmsg_len)
{
	char rp_str[INET_ADDRSTRLEN];
	char group_str[PREFIX2STR_BUFFER];
	int result;

	inet_ntop(AF_INET, &rp_addr, rp_str, sizeof(rp_str));
	prefix2str(&group, group_str, sizeof(group_str));

	result = pim_rp_del(pim, rp_addr, group, plist, RP_SRC_STATIC);

	if (result == PIM_GROUP_BAD_ADDRESS) {
		snprintf(errmsg, errmsg_len,
			 "Bad group address specified: %s", group_str);
		return NB_ERR_INCONSISTENCY;
	}

	if (result == PIM_RP_BAD_ADDRESS) {
		snprintf(errmsg, errmsg_len,
			 "Bad RP address specified: %s", rp_str);
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
	pim_enable_dnode = yang_dnode_get(dnode, "%s/frr-pim:pim/pim-enable",
					  if_xpath);
	igmp_enable_dnode = yang_dnode_get(dnode,
					   "%s/frr-igmp:igmp/igmp-enable",
					   if_xpath);

	if (((pim_enable_dnode) &&
	     (yang_dnode_get_bool(pim_enable_dnode, "."))) ||
	     ((igmp_enable_dnode) &&
	     (yang_dnode_get_bool(igmp_enable_dnode, "."))))
		return true;

	return false;
}

static int pim_cmd_igmp_start(struct interface *ifp)
{
	struct pim_interface *pim_ifp;
	uint8_t need_startup = 0;

	pim_ifp = ifp->info;

	if (!pim_ifp) {
		pim_ifp = pim_if_new(ifp, true, false, false, false);
		need_startup = 1;
	} else {
		if (!PIM_IF_TEST_IGMP(pim_ifp->options)) {
			PIM_IF_DO_IGMP(pim_ifp->options);
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
static void igmp_sock_query_interval_reconfig(struct igmp_sock *igmp)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;

	assert(igmp);

	/* other querier present? */

	if (igmp->t_other_querier_timer)
		return;

	/* this is the querier */

	assert(igmp->interface);
	assert(igmp->interface->info);

	ifp = igmp->interface;
	pim_ifp = ifp->info;

	if (PIM_DEBUG_IGMP_TRACE) {
		char ifaddr_str[INET_ADDRSTRLEN];

		pim_inet4_dump("<ifaddr?>", igmp->ifaddr, ifaddr_str,
				sizeof(ifaddr_str));
		zlog_debug("%s: Querier %s on %s reconfig query_interval=%d",
				__func__, ifaddr_str, ifp->name,
				pim_ifp->igmp_default_query_interval);
	}

	/*
	 * igmp_startup_mode_on() will reset QQI:

	 * igmp->querier_query_interval = pim_ifp->igmp_default_query_interval;
	 */
	igmp_startup_mode_on(igmp);
}

static void igmp_sock_query_reschedule(struct igmp_sock *igmp)
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

static void change_query_interval(struct pim_interface *pim_ifp,
		int query_interval)
{
	struct listnode *sock_node;
	struct igmp_sock *igmp;

	pim_ifp->igmp_default_query_interval = query_interval;

	for (ALL_LIST_ELEMENTS_RO(pim_ifp->igmp_socket_list, sock_node, igmp)) {
		igmp_sock_query_interval_reconfig(igmp);
		igmp_sock_query_reschedule(igmp);
	}
}

static void change_query_max_response_time(struct pim_interface *pim_ifp,
		int query_max_response_time_dsec)
{
	struct listnode *sock_node;
	struct igmp_sock *igmp;

	pim_ifp->igmp_query_max_response_time_dsec =
		query_max_response_time_dsec;

	/*
	 * Below we modify socket/group/source timers in order to quickly
	 * reflect the change. Otherwise, those timers would args->eventually
	 * catch up.
	 */

	/* scan all sockets */
	for (ALL_LIST_ELEMENTS_RO(pim_ifp->igmp_socket_list, sock_node, igmp)) {
		struct listnode *grp_node;
		struct igmp_group *grp;

		/* reschedule socket general query */
		igmp_sock_query_reschedule(igmp);

		/* scan socket groups */
		for (ALL_LIST_ELEMENTS_RO(igmp->igmp_group_list, grp_node,
					grp)) {
			struct listnode *src_node;
			struct igmp_source *src;

			/* reset group timers for groups in EXCLUDE mode */
			if (grp->group_filtermode_isexcl)
				igmp_group_reset_gmi(grp);

			/* scan group sources */
			for (ALL_LIST_ELEMENTS_RO(grp->group_source_list,
						src_node, src)) {

				/* reset source timers for sources with running
				 * timers
				 */
				if (src->t_source_timer)
					igmp_source_reset_gmi(igmp, grp, src);
			}
		}
	}
}

int routing_control_plane_protocols_name_validate(
	struct nb_cb_create_args *args)
{
	const char *name;

	name = yang_dnode_get_string(args->dnode, "./name");
	if (!strmatch(name, "pim")) {
		snprintf(args->errmsg, args->errmsg_len,
				"pim supports only one instance with name pimd");
		return NB_ERR_VALIDATION;
	}
	return NB_OK;
}

/*
 * XPath: /frr-pim:pim/packets
 */
int pim_packets_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-pim:pim/join-prune-interval
 */
int pim_join_prune_interval_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-pim:pim/register-suppress-time
 */
int pim_register_suppress_time_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/ecmp
 */
int routing_control_plane_protocols_control_plane_protocol_pim_ecmp_modify(
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/ecmp-rebalance
 */
int routing_control_plane_protocols_control_plane_protocol_pim_ecmp_rebalance_modify(
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/keep-alive-timer
 */
int routing_control_plane_protocols_control_plane_protocol_pim_keep_alive_timer_modify(
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/rp-keep-alive-timer
 */
int routing_control_plane_protocols_control_plane_protocol_pim_rp_keep_alive_timer_modify(
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
		/* TODO: implement me. */
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
	spt_switch_action = yang_dnode_get_enum(args->dnode, "./spt-action");

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
	struct ipaddr source_addr;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		yang_dnode_get_ip(&source_addr, args->dnode, NULL);
		result = pim_ssmpingd_start(pim, source_addr.ip._v4_addr);
		if (result) {
			char source_str[INET_ADDRSTRLEN];

			ipaddr2str(&source_addr, source_str,
					sizeof(source_str));
			snprintf(args->errmsg, args->errmsg_len,
				 "%% Failure starting ssmpingd for source %s: %d",
				 source_str, result);
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
	struct ipaddr source_addr;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		yang_dnode_get_ip(&source_addr, args->dnode, NULL);
		result = pim_ssmpingd_stop(pim, source_addr.ip._v4_addr);
		if (result) {
			char source_str[INET_ADDRSTRLEN];

			ipaddr2str(&source_addr, source_str,
				   sizeof(source_str));
			snprintf(args->errmsg, args->errmsg_len,
				 "%% Failure stopping ssmpingd for source %s: %d",
				  source_str, result);
			return NB_ERR_INCONSISTENCY;
		}

		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp-mesh-group
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_mesh_group_create(
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

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_mesh_group_destroy(
	struct nb_cb_destroy_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;
	const char *mesh_group_name;
	int result;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		mesh_group_name = yang_dnode_get_string(args->dnode, "mesh-group-name");

		result = ip_no_msdp_mesh_group_cmd_worker(pim, mesh_group_name,
				args->errmsg,
				args->errmsg_len);

		if (result != PIM_MSDP_ERR_NONE)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp-mesh-group/mesh-group-name
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_mesh_group_mesh_group_name_modify(
	struct nb_cb_modify_args *args)
{
	const char *mesh_group_name;
	const char *mesh_group_name_old;
	char xpath[XPATH_MAXLEN];

	switch (args->event) {
	case NB_EV_VALIDATE:
		mesh_group_name = yang_dnode_get_string(args->dnode, ".");
		yang_dnode_get_path(args->dnode, xpath, sizeof(xpath));

		if (yang_dnode_exists(running_config->dnode, xpath) == false)
			break;

		mesh_group_name_old = yang_dnode_get_string(
					running_config->dnode,
					xpath);
		if (strcmp(mesh_group_name, mesh_group_name_old)) {
			/* currently only one mesh-group can exist at a time */
			snprintf(args->errmsg, args->errmsg_len,
				 "Only one mesh-group allowed currently");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_mesh_group_mesh_group_name_destroy(
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp-mesh-group/member-ip
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_mesh_group_member_ip_create(
	struct nb_cb_create_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;
	const char *mesh_group_name;
	struct ipaddr mbr_ip;
	enum pim_msdp_err result;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		mesh_group_name = yang_dnode_get_string(args->dnode,
				"../mesh-group-name");
		yang_dnode_get_ip(&mbr_ip, args->dnode, NULL);

		result = ip_msdp_mesh_group_member_cmd_worker(
				pim, mesh_group_name, mbr_ip.ip._v4_addr,
				args->errmsg, args->errmsg_len);

		if (result != PIM_MSDP_ERR_NONE)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_mesh_group_member_ip_destroy(
	struct nb_cb_destroy_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;
	const char *mesh_group_name;
	struct ipaddr mbr_ip;
	enum pim_msdp_err result;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		mesh_group_name = yang_dnode_get_string(args->dnode,
				"../mesh-group-name");
		yang_dnode_get_ip(&mbr_ip, args->dnode, NULL);

		result = ip_no_msdp_mesh_group_member_cmd_worker(
				pim, mesh_group_name, mbr_ip.ip._v4_addr,
				args->errmsg, args->errmsg_len);

		if (result != PIM_MSDP_ERR_NONE)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp-mesh-group/source-ip
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_mesh_group_source_ip_modify(
	struct nb_cb_modify_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;
	const char *mesh_group_name;
	struct ipaddr src_ip;
	enum pim_msdp_err result;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		mesh_group_name = yang_dnode_get_string(args->dnode,
				"../mesh-group-name");
		yang_dnode_get_ip(&src_ip, args->dnode, NULL);

		result = ip_msdp_mesh_group_source_cmd_worker(
				pim, mesh_group_name, src_ip.ip._v4_addr,
				args->errmsg, args->errmsg_len);

		if (result != PIM_MSDP_ERR_NONE)
			return NB_ERR_INCONSISTENCY;

		break;
	}
	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_mesh_group_source_ip_destroy(
	struct nb_cb_destroy_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;
	const char *mesh_group_name;
	enum pim_msdp_err result;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		mesh_group_name = yang_dnode_get_string(args->dnode,
				"../mesh-group-name");

		result = ip_no_msdp_mesh_group_source_cmd_worker(
				pim, mesh_group_name, args->errmsg,
				args->errmsg_len);

		if (result != PIM_MSDP_ERR_NONE)
			return NB_ERR_INCONSISTENCY;

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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_peer_destroy(
	struct nb_cb_destroy_args *args)
{
	int result;
	struct pim_instance *pim;
	struct ipaddr peer_ip;
	struct vrf *vrf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		yang_dnode_get_ip(&peer_ip, args->dnode, "./peer-ip");
		result = ip_no_msdp_peer_cmd_worker(pim, peer_ip.ip._v4_addr,
				args->errmsg,
				args->errmsg_len);

		if (result)
			return NB_ERR_INCONSISTENCY;

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
	int result;
	struct vrf *vrf;
	struct pim_instance *pim;
	struct ipaddr peer_ip;
	struct ipaddr source_ip;
	const struct lyd_node *mesh_group_name_dnode;
	const char *mesh_group_name;

	switch (args->event) {
	case NB_EV_VALIDATE:
		mesh_group_name_dnode =
			yang_dnode_get(args->dnode,
					"../../msdp-mesh-group/mesh-group-name");
		if (mesh_group_name_dnode) {
			mesh_group_name =
				yang_dnode_get_string(mesh_group_name_dnode,
						".");
			if (strcmp(mesh_group_name, "default")) {
				/* currently only one mesh-group can exist at a
				 * time
				 */
				snprintf(args->errmsg, args->errmsg_len,
					 "%% Only one mesh-group allowed currently");
				return NB_ERR_VALIDATION;
			}
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		yang_dnode_get_ip(&peer_ip, args->dnode, "../peer-ip");
		yang_dnode_get_ip(&source_ip, args->dnode, NULL);

		result = ip_msdp_peer_cmd_worker(pim, peer_ip.ip._v4_addr,
				source_ip.ip._v4_addr,
				args->errmsg,
				args->errmsg_len);

		if (result)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_peer_source_ip_destroy(
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

	ifname = yang_dnode_get_string(args->dnode, "./peerlink-rif");
	ifp = if_lookup_by_name(ifname, VRF_DEFAULT);
	if (!ifp) {
		snprintf(args->errmsg, args->errmsg_len,
			 "No such interface name %s", ifname);
		return;
	}
	role = yang_dnode_get_enum(args->dnode, "./my-role");
	peer_state = yang_dnode_get_bool(args->dnode, "./peer-state");
	yang_dnode_get_ip(&reg_addr, args->dnode, "./reg-address");

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
 * XPath: /frr-interface:lib/interface/frr-pim:pim
 */
int lib_interface_pim_create(struct nb_cb_create_args *args)
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

int lib_interface_pim_destroy(struct nb_cb_destroy_args *args)
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

		if (!pim_cmd_interface_delete(ifp)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Unable to delete interface information %s",
				 ifp->name);
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/pim-enable
 */
int lib_interface_pim_pim_enable_modify(struct nb_cb_modify_args *args)
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
		} else {
			pim_ifp = ifp->info;
			if (!pim_ifp)
				return NB_ERR_INCONSISTENCY;

			if (!pim_cmd_interface_delete(ifp)) {
				snprintf(args->errmsg, args->errmsg_len,
					 "Unable to delete interface information");
				return NB_ERR_INCONSISTENCY;
			}
		}
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/hello-interval
 */
int lib_interface_pim_hello_interval_modify(struct nb_cb_modify_args *args)
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
			yang_dnode_get_uint8(args->dnode, NULL);
		pim_ifp->pim_default_holdtime = -1;
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/hello-holdtime
 */
int lib_interface_pim_hello_holdtime_modify(struct nb_cb_modify_args *args)
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
			yang_dnode_get_uint8(args->dnode, NULL);
		break;
	}

	return NB_OK;

}

int lib_interface_pim_hello_holdtime_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-pim:pim/bfd
 */
int lib_interface_pim_bfd_create(struct nb_cb_create_args *args)
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

int lib_interface_pim_bfd_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-pim:pim/bfd
 */
void lib_interface_pim_bfd_apply_finish(struct nb_cb_apply_finish_args *args)
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
		yang_dnode_get_uint8(args->dnode, "./detect_mult");
	pim_ifp->bfd_config.min_rx =
		yang_dnode_get_uint16(args->dnode, "./min-rx-interval");
	pim_ifp->bfd_config.min_tx =
		yang_dnode_get_uint16(args->dnode, "./min-tx-interval");

	pim_bfd_reg_dereg_all_nbr(ifp);
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/bfd/min-rx-interval
 */
int lib_interface_pim_bfd_min_rx_interval_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-pim:pim/bfd/min-tx-interval
 */
int lib_interface_pim_bfd_min_tx_interval_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-pim:pim/bfd/detect_mult
 */
int lib_interface_pim_bfd_detect_mult_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-pim:pim/bfd/profile
 */
int lib_interface_pim_bfd_profile_modify(struct nb_cb_modify_args *args)
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

int lib_interface_pim_bfd_profile_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-pim:pim/bsm
 */
int lib_interface_pim_bsm_modify(struct nb_cb_modify_args *args)
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
		pim_ifp->bsm_enable = yang_dnode_get_bool(args->dnode, NULL);

		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/unicast-bsm
 */
int lib_interface_pim_unicast_bsm_modify(struct nb_cb_modify_args *args)
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
		pim_ifp->ucast_bsm_accept =
			yang_dnode_get_bool(args->dnode, NULL);

		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/active-active
 */
int lib_interface_pim_active_active_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-pim:pim/dr-priority
 */
int lib_interface_pim_dr_priority_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-pim:pim/address-family
 */
int lib_interface_pim_address_family_create(struct nb_cb_create_args *args)
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

int lib_interface_pim_address_family_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-pim:pim/address-family/use-source
 */
int lib_interface_pim_address_family_use_source_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct ipaddr source_addr;
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
		yang_dnode_get_ip(&source_addr, args->dnode, NULL);

		result = interface_pim_use_src_cmd_worker(
				ifp, source_addr.ip._v4_addr,
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
	struct in_addr source_addr = {INADDR_ANY};
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

		result = interface_pim_use_src_cmd_worker(ifp, source_addr,
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
	const char *plist;
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
		plist = yang_dnode_get_string(args->dnode, NULL);

		if (pim_ifp->boundary_oil_plist)
			XFREE(MTYPE_PIM_INTERFACE, pim_ifp->boundary_oil_plist);

		pim_ifp->boundary_oil_plist =
			XSTRDUP(MTYPE_PIM_INTERFACE, plist);

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
		if (pim_ifp->boundary_oil_plist)
			XFREE(MTYPE_PIM_INTERFACE, pim_ifp->boundary_oil_plist);
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
	struct ipaddr source_addr;
	struct ipaddr group_addr;
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

		oifname = yang_dnode_get_string(args->dnode, "./oif");
		oif = if_lookup_by_name(oifname, pim->vrf_id);

		if (!oif) {
			snprintf(args->errmsg, args->errmsg_len,
					"No such interface name %s",
					oifname);
			return NB_ERR_INCONSISTENCY;
		}

		yang_dnode_get_ip(&source_addr, args->dnode, "./source-addr");
		yang_dnode_get_ip(&group_addr, args->dnode, "./group-addr");

		if (pim_static_del(pim, iif, oif, group_addr.ip._v4_addr,
					source_addr.ip._v4_addr)) {
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
	struct ipaddr source_addr;
	struct ipaddr group_addr;
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
		if (!iif) {
			return NB_OK;
		}

		pim_iifp = iif->info;
		pim = pim_iifp->pim;

		oifname = yang_dnode_get_string(args->dnode, NULL);
		oif = if_lookup_by_name(oifname, pim->vrf_id);

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
		oif = if_lookup_by_name(oifname, pim->vrf_id);
		if (!oif) {
			snprintf(args->errmsg, args->errmsg_len,
				 "No such interface name %s",
				 oifname);
			return NB_ERR_INCONSISTENCY;
		}

		yang_dnode_get_ip(&source_addr, args->dnode, "../source-addr");
		yang_dnode_get_ip(&group_addr, args->dnode, "../group-addr");

		if (pim_static_add(pim, iif, oif, group_addr.ip._v4_addr,
				   source_addr.ip._v4_addr)) {
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
	struct ipaddr rp_addr;
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
		yang_dnode_get_ip(&rp_addr, args->dnode, "./rp-address");

		if (yang_dnode_get(args->dnode, "./group-list")) {
			yang_dnode_get_ipv4p(&group, args->dnode,
					"./group-list");
			apply_mask_ipv4((struct prefix_ipv4 *)&group);
			result = pim_no_rp_cmd_worker(pim, rp_addr.ip._v4_addr,
					group, NULL, args->errmsg,
					args->errmsg_len);
		}

		else if (yang_dnode_get(args->dnode, "./prefix-list")) {
			plist = yang_dnode_get_string(args->dnode,
					"./prefix-list");
			if (!str2prefix("224.0.0.0/4", &group)) {
				flog_err(
					EC_LIB_DEVELOPMENT,
					"Unable to convert 224.0.0.0/4 to prefix");
				return NB_ERR_INCONSISTENCY;
			}

			result = pim_no_rp_cmd_worker(pim, rp_addr.ip._v4_addr,
					group, plist,
					args->errmsg,
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
	struct ipaddr rp_addr;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		yang_dnode_get_ip(&rp_addr, args->dnode, "../rp-address");
		yang_dnode_get_ipv4p(&group, args->dnode, NULL);
		apply_mask_ipv4((struct prefix_ipv4 *)&group);

		return pim_rp_cmd_worker(pim, rp_addr.ip._v4_addr, group,
				NULL, args->errmsg, args->errmsg_len);
	}

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_static_rp_rp_list_group_list_destroy(
	struct nb_cb_destroy_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;
	struct prefix group;
	struct ipaddr rp_addr;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		yang_dnode_get_ip(&rp_addr, args->dnode, "../rp-address");
		yang_dnode_get_ipv4p(&group, args->dnode, NULL);
		apply_mask_ipv4((struct prefix_ipv4 *)&group);

		return pim_no_rp_cmd_worker(pim, rp_addr.ip._v4_addr, group,
				NULL, args->errmsg,
				args->errmsg_len);
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
	struct ipaddr rp_addr;
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
		yang_dnode_get_ip(&rp_addr, args->dnode, "../rp-address");
		if (!str2prefix("224.0.0.0/4", &group)) {
			flog_err(EC_LIB_DEVELOPMENT,
				 "Unable to convert 224.0.0.0/4 to prefix");
			return NB_ERR_INCONSISTENCY;
		}
		return pim_rp_cmd_worker(pim, rp_addr.ip._v4_addr, group,
				plist, args->errmsg, args->errmsg_len);
	}

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_static_rp_rp_list_prefix_list_destroy(
	struct nb_cb_destroy_args *args)
{
	struct vrf *vrf;
	struct pim_instance *pim;
	struct prefix group;
	struct ipaddr rp_addr;
	const char *plist;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pim = vrf->info;
		yang_dnode_get_ip(&rp_addr, args->dnode, "../rp-address");
		plist = yang_dnode_get_string(args->dnode, NULL);
		if (!str2prefix("224.0.0.0/4", &group)) {
			flog_err(EC_LIB_DEVELOPMENT,
				 "Unable to convert 224.0.0.0/4 to prefix");
			return NB_ERR_INCONSISTENCY;
		}
		return pim_no_rp_cmd_worker(pim, rp_addr.ip._v4_addr, group,
				plist, args->errmsg,
				args->errmsg_len);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-igmp:igmp
 */
int lib_interface_igmp_create(struct nb_cb_create_args *args)
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

int lib_interface_igmp_destroy(struct nb_cb_destroy_args *args)
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

		PIM_IF_DONT_IGMP(pim_ifp->options);

		pim_if_membership_clear(ifp);

		pim_if_addr_del_all_igmp(ifp);

		if (!PIM_IF_TEST_PIM(pim_ifp->options))
			pim_if_delete(ifp);
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-igmp:igmp/igmp-enable
 */
int lib_interface_igmp_igmp_enable_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	bool igmp_enable;
	struct pim_interface *pim_ifp;
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
			snprintf(args->errmsg, args->errmsg_len,
				 "Max multicast interfaces(%d) Reached. Could not enable IGMP on interface %s",
				 MAXVIFS, ifp_name);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		igmp_enable = yang_dnode_get_bool(args->dnode, NULL);

		if (igmp_enable)
			return pim_cmd_igmp_start(ifp);

		else {
			pim_ifp = ifp->info;

			if (!pim_ifp)
				return NB_ERR_INCONSISTENCY;

			PIM_IF_DONT_IGMP(pim_ifp->options);

			pim_if_membership_clear(ifp);

			pim_if_addr_del_all_igmp(ifp);

			if (!PIM_IF_TEST_PIM(pim_ifp->options))
				pim_if_delete(ifp);
		}
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-igmp:igmp/version
 */
int lib_interface_igmp_version_modify(struct nb_cb_modify_args *args)
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

int lib_interface_igmp_version_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-igmp:igmp/query-interval
 */
int lib_interface_igmp_query_interval_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;
	int query_interval;
	int query_interval_dsec;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		pim_ifp = ifp->info;
		query_interval = yang_dnode_get_uint16(args->dnode, NULL);
		query_interval_dsec = 10 * query_interval;
		if (query_interval_dsec <=
				pim_ifp->igmp_query_max_response_time_dsec) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Can't set general query interval %d dsec <= query max response time %d dsec.",
				 query_interval_dsec,
				 pim_ifp->igmp_query_max_response_time_dsec);
			return NB_ERR_INCONSISTENCY;
		}
		change_query_interval(pim_ifp, query_interval);
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-igmp:igmp/query-max-response-time
 */
int lib_interface_igmp_query_max_response_time_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;
	int query_max_response_time_dsec;
	int default_query_interval_dsec;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		pim_ifp = ifp->info;
		query_max_response_time_dsec =
			yang_dnode_get_uint8(args->dnode, NULL);
		default_query_interval_dsec =
			10 * pim_ifp->igmp_default_query_interval;

		if (query_max_response_time_dsec
			>= default_query_interval_dsec) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Can't set query max response time %d sec >= general query interval %d sec",
				 query_max_response_time_dsec,
				 pim_ifp->igmp_default_query_interval);
			return NB_ERR_INCONSISTENCY;
		}

		change_query_max_response_time(pim_ifp,
				query_max_response_time_dsec);
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-igmp:igmp/last-member-query-interval
 */
int lib_interface_igmp_last_member_query_interval_modify(
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
		last_member_query_interval = yang_dnode_get_uint8(args->dnode,
				NULL);
		pim_ifp->igmp_specific_query_max_response_time_dsec =
			last_member_query_interval;

		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-igmp:igmp/robustness-variable
 */
int lib_interface_igmp_robustness_variable_modify(
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
		last_member_query_count = yang_dnode_get_uint8(args->dnode,
				NULL);
		pim_ifp->igmp_last_member_query_count = last_member_query_count;

		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-igmp:igmp/address-family
 */
int lib_interface_igmp_address_family_create(struct nb_cb_create_args *args)
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

int lib_interface_igmp_address_family_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-igmp:igmp/address-family/static-group
 */
int lib_interface_igmp_address_family_static_group_create(
	struct nb_cb_create_args *args)
{
	struct interface *ifp;
	struct ipaddr source_addr;
	struct ipaddr group_addr;
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
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		yang_dnode_get_ip(&source_addr, args->dnode, "./source-addr");
		yang_dnode_get_ip(&group_addr, args->dnode, "./group-addr");

		result = pim_if_igmp_join_add(ifp, group_addr.ip._v4_addr,
				source_addr.ip._v4_addr);
		if (result) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Failure joining IGMP group");
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int lib_interface_igmp_address_family_static_group_destroy(
	struct nb_cb_destroy_args *args)
{
	struct interface *ifp;
	struct ipaddr source_addr;
	struct ipaddr group_addr;
	int result;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		yang_dnode_get_ip(&source_addr, args->dnode, "./source-addr");
		yang_dnode_get_ip(&group_addr, args->dnode, "./group-addr");

		result = pim_if_igmp_join_del(ifp, group_addr.ip._v4_addr,
				source_addr.ip._v4_addr);

		if (result) {
			char src_str[INET_ADDRSTRLEN];
			char grp_str[INET_ADDRSTRLEN];

			ipaddr2str(&source_addr, src_str, sizeof(src_str));
			ipaddr2str(&group_addr, grp_str, sizeof(grp_str));

			snprintf(args->errmsg, args->errmsg_len,
				 "%% Failure leaving IGMP group %s %s on interface %s: %d",
				 src_str, grp_str, ifp->name, result);

			return NB_ERR_INCONSISTENCY;
		}

		break;
	}

	return NB_OK;
}
