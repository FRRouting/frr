/*
 * Copyright (C) 1997, 1998, 1999 Kunihiro Ishiguro <kunihiro@zebra.org>
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Renato Westphal
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

#include "if.h"
#include "vrf.h"
#include "log.h"
#include "prefix.h"
#include "table.h"
#include "command.h"
#include "routemap.h"
#include "northbound.h"
#include "libfrr.h"
#include "lib_errors.h"
#include "pimd/pimd.h"
#include "pimd/pim_nb.h"
#include "lib/vty.h"
#include "pimd/pim_ssm.h"
#include "pimd/pim_bfd.h"
#include "pimd/pim_pim.h"
#include "pimd/pim_ssmpingd.h"
#include "pimd/pim_mlag.h"
#include "pimd/pim_vxlan.h"
#include "pimd/pim_errors.h"
#include "pimd/pim_static.h"

void change_query_max_response_time(struct pim_interface *pim_ifp,
                                           int query_max_response_time_dsec);
void change_query_interval(struct pim_interface *pim_ifp,
                                  int query_interval);
void pim_if_membership_refresh(struct interface *ifp);
void pim_if_membership_clear(struct interface *ifp);
void pim_ssm_range_reevaluate(struct pim_instance *pim);
void detect_address_change(struct interface *ifp, int force_prim_as_any,
                           const char *caller);
int pim_update_source_set(struct interface *ifp, struct in_addr source);

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
                        pim->spt.plist =
                                XSTRDUP(MTYPE_PIM_PLIST_NAME, plist);
                break;
        }
        
        return CMD_SUCCESS;
}

static int pim_rp_cmd_worker(struct pim_instance *pim, struct in_addr rp_addr,
                             struct prefix group, const char *plist)
{       
	char rp_str[INET_ADDRSTRLEN];
	char group_str[PREFIX2STR_BUFFER];
        int result;

	inet_ntop(AF_INET, &rp_addr, rp_str, sizeof(rp_str));
	prefix2str(&group, group_str, sizeof(group_str));
 
        result = pim_rp_new(pim, rp_addr, group, plist, RP_SRC_STATIC);
        
        if (result == PIM_GROUP_BAD_ADDR_MASK_COMBO) {
		flog_warn(EC_PIM_CONFIG,
			"%s: Inconsistent address and mask %s",
			__func__, group_str);
                return CMD_WARNING_CONFIG_FAILED;
        }
        
        if (result == PIM_GROUP_BAD_ADDRESS) {
                flog_warn(EC_PIM_CONFIG,
			"%s: Bad group address specified %s",
			__func__, group_str);
                return CMD_WARNING_CONFIG_FAILED;
        }
        
        if (result == PIM_RP_BAD_ADDRESS) {
                flog_warn(EC_PIM_CONFIG,
			"%s: Bad RP address specified %s",
			__func__, rp_str);
                return CMD_WARNING_CONFIG_FAILED;
        }
        
        if (result == PIM_RP_NO_PATH) {
                flog_warn(EC_PIM_CONFIG,
			"%s: No Path to RP address specified %s",
			__func__, rp_str);
                return CMD_WARNING;
        }
        
        if (result == PIM_GROUP_OVERLAP) {
		flog_warn(EC_PIM_CONFIG,
                        "%s: Group range specified cannot exact match another",
			__func__);
                return CMD_WARNING_CONFIG_FAILED;
        }
        
        if (result == PIM_GROUP_PFXLIST_OVERLAP) {
                flog_warn(EC_PIM_CONFIG,
                        "%s This group is already covered by a RP prefix-list",
			__func__);
                return CMD_WARNING_CONFIG_FAILED;
        }
        
        if (result == PIM_RP_PFXLIST_IN_USE) {
		flog_warn(EC_PIM_CONFIG,
                        "%s The same prefix-list cannot be applied to multiple RPs",
			__func__);
                return CMD_WARNING_CONFIG_FAILED;
	}

        return CMD_SUCCESS;
}

static int pim_no_rp_cmd_worker(struct pim_instance *pim,
				struct in_addr rp_addr, struct prefix group,
                                const char *plist)
{
        char rp_str[INET_ADDRSTRLEN];
        char group_str[PREFIX2STR_BUFFER];
        int result;

        inet_ntop(AF_INET, &rp_addr, rp_str, sizeof(rp_str));
        prefix2str(&group, group_str, sizeof(group_str));

	result = pim_rp_del(pim, rp_addr, group, plist, RP_SRC_STATIC);

        if (result == PIM_GROUP_BAD_ADDRESS) {
                flog_warn(EC_PIM_CONFIG,
			"%s: Bad group address specified: %s",
			__func__, group_str);
                return CMD_WARNING_CONFIG_FAILED;
        }

        if (result == PIM_RP_BAD_ADDRESS) {
                flog_warn(EC_PIM_CONFIG,
			"%s: Bad RP address specified: %s",
			__func__, rp_str);
                return CMD_WARNING_CONFIG_FAILED;
        }

        if (result == PIM_RP_NOT_FOUND) {
                flog_warn(EC_PIM_CONFIG,
			"%s: Unable to find specified RP %s",
			__func__, rp_str);
                return CMD_WARNING_CONFIG_FAILED;
        }

        return CMD_SUCCESS;
}

static int pim_ssm_cmd_worker(struct pim_instance *pim,
                              const char *plist)
{
        int result = pim_ssm_range_set(pim, pim->vrf_id, plist);
        int ret = CMD_WARNING_CONFIG_FAILED;

        if (result == PIM_SSM_ERR_NONE)
                return CMD_SUCCESS;

        switch (result) {
        case PIM_SSM_ERR_NO_VRF:
		flog_warn(EC_PIM_CONFIG,
                	"%s: VRF doesn't exist",
			__func__);
                break;
        case PIM_SSM_ERR_DUP:
                flog_warn(EC_PIM_CONFIG,
			"%s: duplicate config",
			__func__);
                ret = CMD_WARNING;
                break;
        default:
                flog_warn(EC_PIM_CONFIG,
			"%s: ssm range config failed",
			__func__);
        }

        return ret;
}

static int pim_cmd_igmp_start(struct interface *ifp)
{
        struct pim_interface *pim_ifp;
        uint8_t need_startup = 0;

        pim_ifp = ifp->info;

        if (!pim_ifp) {
                (void)pim_if_new(ifp, true, false, false, false);
                need_startup = 1;
        } else {
                if (!PIM_IF_TEST_IGMP(pim_ifp->options)) {
                        PIM_IF_DO_IGMP(pim_ifp->options);
                        need_startup = 1;
                }
        }

        /* 'ip igmp' executed multiple times, with need_startup
          avoid multiple if add all and membership refresh */
        if (need_startup) {
                pim_if_addr_add_all(ifp);
                pim_if_membership_refresh(ifp);
        }

        return CMD_SUCCESS;
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
          pim_sock_delete() removes all neighbors from
          pim_ifp->pim_neighbor_list.
         */
        pim_sock_delete(ifp, "pim unconfigured on interface");

        if (!PIM_IF_TEST_IGMP(pim_ifp->options)) {
                pim_if_addr_del_all(ifp);
                pim_if_delete(ifp);
        }

        return 1;
}

static int interface_pim_use_src_cmd_worker(struct interface *ifp, struct in_addr source_addr)
{
        int result;
        int ret = CMD_SUCCESS;

        result = pim_update_source_set(ifp, source_addr);

        switch (result) {
        case PIM_SUCCESS:
                break;
        case PIM_IFACE_NOT_FOUND:
                ret = CMD_WARNING_CONFIG_FAILED;
                flog_warn(EC_PIM_CONFIG,
			"%s: Pim not enabled on this interface %s",
			__func__, ifp->name);
                break;
        case PIM_UPDATE_SOURCE_DUP:
                ret = CMD_WARNING;
                flog_warn(EC_PIM_CONFIG, "%s: Source already set",
			__func__);
                break;
        default:
                ret = CMD_WARNING_CONFIG_FAILED;
                flog_warn(EC_PIM_CONFIG, "%s: Source set failed", __func__);
        }

        return ret;
}

static int ip_msdp_mesh_group_member_cmd_worker(struct pim_instance *pim,
                                                const char *mg,
                                                struct in_addr mbr_ip)
{
        enum pim_msdp_err result;
        int ret = CMD_SUCCESS;

        result = pim_msdp_mg_mbr_add(pim, mg, mbr_ip);

        switch (result) {
        case PIM_MSDP_ERR_NONE:
                break;
        case PIM_MSDP_ERR_OOM:
                ret = CMD_WARNING_CONFIG_FAILED;
                flog_warn(EC_PIM_CONFIG,
			"%s: Out of memory", __func__);
                break;
        case PIM_MSDP_ERR_MG_MBR_EXISTS:
                ret = CMD_WARNING;
                flog_warn(EC_PIM_CONFIG, "%s: mesh-group member exists", __func__);
                break;
        case PIM_MSDP_ERR_MAX_MESH_GROUPS:
                ret = CMD_WARNING_CONFIG_FAILED;
                flog_warn(EC_PIM_CONFIG,
			"%s: Only one mesh-group allowed currently", __func__);
                break;
        default:
                ret = CMD_WARNING_CONFIG_FAILED;
                flog_warn(EC_PIM_CONFIG, "%s: member add failed", __func__);
        }

        return ret;
}

static int ip_no_msdp_mesh_group_member_cmd_worker(struct pim_instance *pim,
                                                   const char *mg,
                                                   struct in_addr mbr_ip)
{
        enum pim_msdp_err result;

        result = pim_msdp_mg_mbr_del(pim, mg, mbr_ip);

        switch (result) {
        case PIM_MSDP_ERR_NONE:
                break;
        case PIM_MSDP_ERR_NO_MG:
                flog_warn(EC_PIM_CONFIG, "%s: mesh-group does not exist", __func__);
                break;
        case PIM_MSDP_ERR_NO_MG_MBR:
                flog_warn(EC_PIM_CONFIG, "%s: mesh-group member does not exist", __func__);
                break;
        default:
                flog_warn(EC_PIM_CONFIG, "%s: mesh-group member del failed", __func__);
        }

        return result ? CMD_WARNING_CONFIG_FAILED : CMD_SUCCESS;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim
 */
int routing_control_plane_protocols_control_plane_protocol_pim_create(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
{
	const char *vrf_name;
	struct vrf *vrf;

        switch (event) {
        case NB_EV_VALIDATE:
        case NB_EV_PREPARE:
        case NB_EV_ABORT:
                break;
        case NB_EV_APPLY:
		vrf_name = yang_dnode_get_string(dnode, "/frr-routing:routing/control-plane-protocols/control-plane-protocol/vrf");
		vrf = vrf_lookup_by_name(vrf_name);
		nb_running_set_entry(dnode, vrf->info);
        }

        return NB_OK;
}


/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim
 */
int routing_control_plane_protocols_control_plane_protocol_pim_destroy(enum nb_event event, const struct lyd_node *dnode)
{

        return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/ecmp
 */
int routing_control_plane_protocols_control_plane_protocol_pim_ecmp_create(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
{
	struct pim_instance *pim;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		pim = nb_running_get_entry(dnode, NULL, true);
		pim->ecmp_enable = true;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/ecmp
 */
int routing_control_plane_protocols_control_plane_protocol_pim_ecmp_destroy(enum nb_event event, const struct lyd_node *dnode)
{
        struct pim_instance *pim;

        switch (event) {
        case NB_EV_VALIDATE:
        case NB_EV_PREPARE:
        case NB_EV_ABORT:
                break;
        case NB_EV_APPLY:
		pim = nb_running_get_entry(dnode, NULL, true);
                pim->ecmp_enable = false;
        }

        return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/ecmp-rebalance
 */
int routing_control_plane_protocols_control_plane_protocol_pim_ecmp_rebalance_create(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
{
	struct pim_instance *pim;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		pim = nb_running_get_entry(dnode, NULL, true);
		pim->ecmp_rebalance_enable = true;
	}

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_pim_ecmp_rebalance_destroy(enum nb_event event, const struct lyd_node *dnode)
{
        struct pim_instance *pim;

        switch (event) {
        case NB_EV_VALIDATE:
        case NB_EV_PREPARE:
        case NB_EV_ABORT:
                break;
        case NB_EV_APPLY:
		pim = nb_running_get_entry(dnode, NULL, true);
                pim->ecmp_rebalance_enable = false;

        }

        return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/join-prune-interval
 */
int routing_control_plane_protocols_control_plane_protocol_pim_join_prune_interval_modify(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		router->t_periodic = yang_dnode_get_uint16(dnode, NULL);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/keep-alive-timer
 */
int routing_control_plane_protocols_control_plane_protocol_pim_keep_alive_timer_modify(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)

{
	struct pim_instance *pim;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		pim = nb_running_get_entry(dnode, NULL, true);
		pim->keep_alive_time = yang_dnode_get_uint16(dnode, NULL);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/rp-keep-alive-timer
 */
int routing_control_plane_protocols_control_plane_protocol_pim_rp_keep_alive_timer_modify(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
{
        struct pim_instance *pim;

        switch (event) {
        case NB_EV_VALIDATE:
        case NB_EV_PREPARE:
        case NB_EV_ABORT:
                break;
        case NB_EV_APPLY:
		pim = nb_running_get_entry(dnode, NULL, true);
                pim->rp_keep_alive_time = yang_dnode_get_uint16(dnode, NULL);
                break;
        }

        return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/packets
 */
int routing_control_plane_protocols_control_plane_protocol_pim_packets_modify(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		router->packet_process = yang_dnode_get_uint8(dnode, NULL);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/register-suppress-time
 */
int routing_control_plane_protocols_control_plane_protocol_pim_register_suppress_time_modify(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)

{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		router->packet_process = yang_dnode_get_uint16(dnode, NULL);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_create(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_destroy(enum nb_event event, const struct lyd_node *dnode)
{
	switch (event) {
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
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_send_v6_secondary_create(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
{
	struct pim_instance *pim;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		pim = nb_running_get_entry(dnode, NULL, true);
		pim->send_v6_secondary = 1;
		break;
	}

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_send_v6_secondary_destroy(enum nb_event event, const struct lyd_node *dnode)

{
        struct pim_instance *pim;

        switch (event) {
        case NB_EV_VALIDATE:
        case NB_EV_PREPARE:
        case NB_EV_ABORT:
                break;
        case NB_EV_APPLY:
		pim = nb_running_get_entry(dnode, NULL, true);
                pim->send_v6_secondary = 0;
                break;
        }

        return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/spt-switchover/spt-action
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_spt_switchover_spt_action_modify(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
{
        struct pim_instance *pim;
        int spt_switch_action;
        const char *prefix_list = NULL;

        switch (event) {
        case NB_EV_VALIDATE:
        case NB_EV_PREPARE:
        case NB_EV_ABORT:
                break;
        case NB_EV_APPLY:
		pim = nb_running_get_entry(dnode, NULL, true);
                spt_switch_action = yang_dnode_get_enum(dnode, NULL);

                switch (spt_switch_action) {
                case PIM_SPT_INFINITY:
			if (yang_dnode_exists(dnode, "../spt-infinity-prefix-list"))
                        	prefix_list = yang_dnode_get_string(dnode, "../spt-infinity-prefix-list");
                   	
			pim_cmd_spt_switchover(pim, PIM_SPT_INFINITY, prefix_list);
                        break;
                case PIM_SPT_IMMEDIATE:
                        pim_cmd_spt_switchover(pim, PIM_SPT_IMMEDIATE, NULL);
                        break;
                }

                break;
        }

        return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/spt-switchover/spt-infinity-prefix-list
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_spt_switchover_spt_infinity_prefix_list_modify(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
{
	switch (event) {
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
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_spt_switchover_spt_infinity_prefix_list_destroy(enum nb_event event, const struct lyd_node *dnode)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/ssm/prefix-list
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_ssm_prefix_list_modify(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)

{
	struct pim_instance *pim;
	const char *plist_name;
	int result ;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		pim = nb_running_get_entry(dnode, NULL, true);
		plist_name = yang_dnode_get_string(dnode, NULL);	
		result = pim_ssm_cmd_worker(pim, plist_name);

		if (result)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/spt-switchover/spt-infinity-prefix-list
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_ssm_prefix_list_destroy(enum nb_event event, const struct lyd_node *dnode)
{
        struct pim_instance *pim;
        int result ;

        switch (event) {
        case NB_EV_VALIDATE:
        case NB_EV_PREPARE:
        case NB_EV_ABORT:
                break;
        case NB_EV_APPLY:
                pim = nb_running_get_entry(dnode, NULL, true);
                result = pim_ssm_cmd_worker(pim, NULL);

                if (result)
                        return NB_ERR_INCONSISTENCY;

		break;
	}

        return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/ssm-pingd/source-ip
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_ssm_pingd_source_ip_create(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
{
        struct pim_instance *pim;
        int result;
        struct ipaddr source_addr;

        switch (event) {
        case NB_EV_VALIDATE:
        case NB_EV_PREPARE:
        case NB_EV_ABORT:
                break;
        case NB_EV_APPLY:
		pim = nb_running_get_entry(dnode, NULL, true);
		yang_dnode_get_ip(&source_addr, dnode, NULL);
		result = pim_ssmpingd_start(pim, source_addr.ip._v4_addr);
		if (result) {
			char source_str[INET_ADDRSTRLEN];

			ipaddr2str(&source_addr, source_str, sizeof(source_str));
                	flog_warn(EC_LIB_NB_CB_CONFIG_APPLY, "%s: Failure starting ssmpingd for source %s: %d",
                        	__func__, source_str, result);
			return NB_ERR_INCONSISTENCY;
        	}

                break;
        }

        return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_ssm_pingd_source_ip_destroy(enum nb_event event, const struct lyd_node *dnode)
{       
        struct pim_instance *pim;
        int result;
        struct ipaddr source_addr;
 
        switch (event) {
        case NB_EV_VALIDATE:
        case NB_EV_PREPARE:
        case NB_EV_ABORT:
                break;
        case NB_EV_APPLY:
                pim = nb_running_get_entry(dnode, NULL, true);
		yang_dnode_get_ip(&source_addr, dnode, NULL);
                result = pim_ssmpingd_stop(pim, source_addr.ip._v4_addr);
                if (result) {
			char source_str[INET_ADDRSTRLEN];

			ipaddr2str(&source_addr, source_str, sizeof(source_str));
                        flog_warn(EC_LIB_NB_CB_CONFIG_APPLY,
				"%s: Failure stoping ssmpingd for source %s: %d",
                                __func__, source_str, result);
                    return NB_ERR_VALIDATION;
                }
                
                break;
        }
        
        return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp/msdp-mesh-group/mesh-group-name
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_msdp_mesh_group_mesh_group_name_modify(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_msdp_mesh_group_mesh_group_name_destroy(enum nb_event event, const struct lyd_node *dnode)
{
	struct pim_instance *pim;
	const char *mg;

        switch (event) {
        case NB_EV_VALIDATE:
        case NB_EV_PREPARE:
        case NB_EV_ABORT:
                break;
        case NB_EV_APPLY:
		pim = nb_running_get_entry(dnode, NULL, true);
		mg = yang_dnode_get_string(dnode, "../mesh-group-name");
		pim_msdp_mg_del(pim, mg);

		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp/msdp-mesh-group/member-ip
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_msdp_mesh_group_member_ip_create(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
{
	struct pim_instance *pim;
	const char *mg;
	struct ipaddr mbr_ip;
	enum pim_msdp_err result;

        switch (event) {
        case NB_EV_VALIDATE:
        case NB_EV_PREPARE:
        case NB_EV_ABORT:
                break;
        case NB_EV_APPLY:
		pim = nb_running_get_entry(dnode, NULL, true);
		mg = yang_dnode_get_string(dnode, "../mesh-group-name");
		yang_dnode_get_ip(&mbr_ip, dnode, NULL);	

		result = ip_msdp_mesh_group_member_cmd_worker(pim, mg, mbr_ip.ip._v4_addr);

		if (result != PIM_MSDP_ERR_NONE)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_msdp_mesh_group_member_ip_destroy(enum nb_event event, const struct lyd_node *dnode)
{
	struct pim_instance *pim;
	const char *mg;
	struct ipaddr mbr_ip;
	enum pim_msdp_err result;

        switch (event) {
        case NB_EV_VALIDATE:
        case NB_EV_PREPARE:
        case NB_EV_ABORT:
                break;
        case NB_EV_APPLY:
		pim = nb_running_get_entry(dnode, NULL, true);
        	mg = yang_dnode_get_string(dnode, "../mesh-group-name");
        	yang_dnode_get_ip(&mbr_ip, dnode, NULL);

        	result = ip_no_msdp_mesh_group_member_cmd_worker(pim, mg, mbr_ip.ip._v4_addr);

		if (result != PIM_MSDP_ERR_NONE)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}
	
/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp/msdp-mesh-group/source-ip
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_msdp_mesh_group_source_ip_modify(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
{
	struct pim_instance *pim;
	const char *mg;
        struct ipaddr src_ip;
	enum pim_msdp_err result;

        switch (event) {
        case NB_EV_VALIDATE:
        case NB_EV_PREPARE:
        case NB_EV_ABORT:
                break;
        case NB_EV_APPLY:
		pim = nb_running_get_entry(dnode, NULL, true);
		mg = yang_dnode_get_string(dnode, "../mesh-group-name");
		yang_dnode_get_ip(&src_ip, dnode, NULL);

		result = pim_msdp_mg_src_add(pim, mg, src_ip.ip._v4_addr);

                if (result != PIM_MSDP_ERR_NONE)
                        return NB_ERR_INCONSISTENCY;

		break;
	}
	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_msdp_mesh_group_source_ip_destroy(enum nb_event event, const struct lyd_node *dnode)
{
	struct pim_instance *pim;
        const char *mg;
	enum pim_msdp_err result;
        
        switch (event) {
        case NB_EV_VALIDATE:
        case NB_EV_PREPARE:
        case NB_EV_ABORT:
                break;
        case NB_EV_APPLY:
		pim = nb_running_get_entry(dnode, NULL, true);
        	mg = yang_dnode_get_string(dnode, "../mesh-group-name");

		result = pim_msdp_mg_src_del(pim, mg);

		if (result != PIM_MSDP_ERR_NONE)
			return NB_ERR_INCONSISTENCY;

		break;
	}
	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp/msdp-peer/peer
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_msdp_peer_peer_create(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)

{

        switch (event) {
        case NB_EV_VALIDATE:
        case NB_EV_PREPARE:
        case NB_EV_ABORT:
                break;
        case NB_EV_APPLY:
		break;
	}		
	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_msdp_peer_peer_destroy(enum nb_event event, const struct lyd_node *dnode)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
			break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp/msdp-peer/peer/source-ip
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_msdp_peer_peer_source_ip_modify(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_msdp_peer_peer_source_ip_destroy(enum nb_event event, const struct lyd_node *dnode)
{
	switch (event) {
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
void routing_control_plane_protocols_control_plane_protocol_pim_address_family_mlag_apply_finish(const struct lyd_node *dnode)
{
	const char *ifname;
	uint32_t role;
	bool peer_state;
	struct interface *ifp;
	struct ipaddr reg_addr;
//	char peerlink_rif_xpath[VTY_BUFSIZ];

	ifname = yang_dnode_get_string(dnode, "./peerlink-rif");
        ifp = if_lookup_by_name(ifname, VRF_DEFAULT);
        if (!ifp) {
                flog_warn(EC_PIM_CONFIG, "%s: No such interface name %s\n", __func__, ifname);
                return;
        }
/*	sprintf(peerlink_rif_xpath, "/frr-interface:lib/interface[name=%s][vrf='default']", ifname);
	ifp = nb_running_get_entry(dnode, peerlink_rif_xpath, false);
        if (!ifp) {
               	return NB_ERR_INCONSISTENCY;
        }
*/
	role  = yang_dnode_get_enum(dnode, "./my-role");
	peer_state = yang_dnode_get_bool(dnode, "./peer-state")	;
	yang_dnode_get_ip(&reg_addr, dnode, "./reg-address");	
		
	pim_vxlan_mlag_update(true, peer_state, role, ifp, &reg_addr.ip._v4_addr);

}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/mlag/peerlink-rif
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_mlag_peerlink_rif_modify(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_mlag_peerlink_rif_destroy(enum nb_event event, const struct lyd_node *dnode)
{
	switch (event) {
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
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_mlag_reg_address_modify(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_mlag_reg_address_destroy(enum nb_event event, const struct lyd_node *dnode)
{
	switch (event) {
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
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_mlag_my_role_modify(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
{
	switch (event) {
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
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_mlag_peer_state_modify(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
{
	switch (event) {
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
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_register_accept_list_modify(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
{
        struct pim_instance *pim;
        const char *plist;

        switch (event) {
        case NB_EV_VALIDATE:
        case NB_EV_PREPARE:
        case NB_EV_ABORT:
                break;
        case NB_EV_APPLY:
                pim = nb_running_get_entry(dnode, NULL, true);
		plist = yang_dnode_get_string(dnode, NULL);

		XFREE(MTYPE_PIM_PLIST_NAME, pim->register_plist);
		pim->register_plist = XSTRDUP(MTYPE_PIM_PLIST_NAME, plist);

		break;
	}

        return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_pim_address_family_register_accept_list_destroy(enum nb_event event, const struct lyd_node *dnode)
{
        struct pim_instance *pim;

        switch (event) {
        case NB_EV_VALIDATE:
        case NB_EV_PREPARE:
        case NB_EV_ABORT:
                break;
        case NB_EV_APPLY:
                pim = nb_running_get_entry(dnode, NULL, true);

		XFREE(MTYPE_PIM_PLIST_NAME, pim->register_plist);
		break;
	}

        return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/pim-enable
 */
int lib_interface_pim_pim_enable_create(enum nb_event event,
                        const struct lyd_node *dnode,
                        union nb_resource *resource)
{
	struct interface *ifp;

        switch (event) {
        case NB_EV_VALIDATE:
        case NB_EV_PREPARE:
        case NB_EV_ABORT:
                break;
        case NB_EV_APPLY:
                ifp = nb_running_get_entry(dnode, NULL, true);
		if (!pim_cmd_interface_add(ifp)) {
			flog_warn(EC_PIM_CONFIG, "%s: Could not enable PIM SM on interface %s",
				__func__,ifp->name);
                	return NB_ERR_INCONSISTENCY;
        	}

		break;
	}

        return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/pim-enable
 */
int lib_interface_pim_pim_enable_destroy(enum nb_event event,
                        const struct lyd_node *dnode)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;

        switch (event) {
        case NB_EV_VALIDATE:
        case NB_EV_PREPARE:
        case NB_EV_ABORT:
                break;
        case NB_EV_APPLY:
                ifp = nb_running_get_entry(dnode, NULL, true);
		pim_ifp =ifp->info; 

		if (!pim_ifp)
                	return NB_OK;

                if (!pim_cmd_interface_delete(ifp)) { 
                        flog_warn(EC_PIM_CONFIG, "%s: Unable to delete interface information %s",
                                __func__, ifp->name); 
                        return NB_ERR_INCONSISTENCY;
                }

                break;
        }

        return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/dr-priority
 */
int lib_interface_pim_dr_priority_modify(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;
	uint32_t old_dr_prio;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(dnode, NULL, true);
		pim_ifp = ifp->info;

		if (!pim_ifp)
			return NB_ERR_NOT_FOUND;

		old_dr_prio = pim_ifp->pim_dr_priority;

		pim_ifp->pim_dr_priority = yang_dnode_get_uint32(dnode, NULL); 

		if (old_dr_prio != pim_ifp->pim_dr_priority) {
			pim_if_dr_election(ifp);
			pim_hello_restart_now(ifp);
		}
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/hello-interval
 */
int lib_interface_pim_hello_interval_modify(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_ABORT:
	case NB_EV_PREPARE:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(dnode, NULL, true);
		pim_ifp = ifp->info;

		if (!pim_ifp)
			return NB_ERR_NOT_FOUND;

		pim_ifp->pim_hello_period = yang_dnode_get_uint16(dnode, NULL);
		break;
	}

	return NB_OK;				
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/hello-holdtime
 */
int lib_interface_pim_hello_holdtime_modify(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_ABORT:
	case NB_EV_PREPARE:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(dnode, NULL, true);
		pim_ifp = ifp->info;

		if (!pim_ifp)
			return NB_ERR_NOT_FOUND;

		pim_ifp->pim_default_holdtime =
		    yang_dnode_get_uint16(dnode, NULL);
		break;
	}

	return NB_OK;
}

int lib_interface_pim_hello_holdtime_destroy(enum nb_event event, const struct lyd_node *dnode)
{
	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/bfd
 */
int lib_interface_pim_bfd_create(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)

{
	return NB_OK;
}

int lib_interface_pim_bfd_destroy(enum nb_event event, const struct lyd_node *dnode)
{
        struct interface *ifp;
        struct pim_interface *pim_ifp;

        switch (event) {
        case NB_EV_VALIDATE:
        case NB_EV_ABORT:
        case NB_EV_PREPARE:
                break;
        case NB_EV_APPLY:
                ifp = nb_running_get_entry(dnode, NULL, true);
                pim_ifp = ifp->info;

		if (!pim_ifp)
			return NB_ERR_NOT_FOUND;

        	if (pim_ifp->bfd_info) {
                	pim_bfd_reg_dereg_all_nbr(ifp, ZEBRA_BFD_DEST_DEREGISTER);
                	bfd_info_free(&(pim_ifp->bfd_info));
        	}
		break;
	}

        return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/bfd
 */
void lib_interface_pim_bfd_apply_finish(const struct lyd_node *dnode)
{
        struct interface *ifp;
        struct pim_interface *pim_ifp;
        uint32_t min_rx;
        uint32_t min_tx;
        uint8_t detect_mult;

                ifp = nb_running_get_entry(dnode, NULL, true);
                pim_ifp = ifp->info;

                min_rx = yang_dnode_get_uint16(dnode, "./min-rx-interval");
                min_tx = yang_dnode_get_uint16(dnode, "./min-tx-interval");
                detect_mult = yang_dnode_get_uint8(dnode, "./detect_mult");
                
                if ((min_rx == BFD_DEF_MIN_RX) && (min_tx == BFD_DEF_MIN_TX)
                        && (detect_mult == BFD_DEF_DETECT_MULT)) 
                        pim_bfd_if_param_set(ifp, min_rx, min_tx,
                                     detect_mult, 1);
                else
                        pim_bfd_if_param_set(ifp, min_rx, min_tx,
                                     detect_mult, 0);

		nb_running_set_entry(dnode, pim_ifp->bfd_info);


}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/bfd/min-rx-interval
 */
int lib_interface_pim_bfd_min_rx_interval_modify(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
{
	switch (event) {
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
int lib_interface_pim_bfd_min_tx_interval_modify(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
{
	switch (event) {
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
int lib_interface_pim_bfd_detect_mult_modify(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/bsm
 */
int lib_interface_pim_bsm_create(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(dnode, NULL, true);
		pim_ifp = ifp->info;

		if (!pim_ifp)
			return NB_ERR_NOT_FOUND;

		pim_ifp->bsm_enable = true;

		break;
	}

	return NB_OK;
}

int lib_interface_pim_bsm_destroy(enum nb_event event, const struct lyd_node *dnode)
{
        struct interface *ifp;
        struct pim_interface *pim_ifp;

        switch (event) {
        case NB_EV_VALIDATE:
        case NB_EV_PREPARE:
        case NB_EV_ABORT:
                break;
        case NB_EV_APPLY:
                ifp = nb_running_get_entry(dnode, NULL, true);
                pim_ifp = ifp->info;

		if (!pim_ifp)
			return NB_ERR_NOT_FOUND;
                
                pim_ifp->bsm_enable = false;

                break;
        }

        return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/unicast-bsm
 */
int lib_interface_pim_unicast_bsm_create(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(dnode, NULL, true);
		pim_ifp = ifp->info;

                if (!pim_ifp)
                        return NB_ERR_NOT_FOUND;

		pim_ifp->ucast_bsm_accept = true;

		break;
	}

	return NB_OK;
}

int lib_interface_pim_unicast_bsm_destroy(enum nb_event event, const struct lyd_node *dnode)
{
        struct interface *ifp;
        struct pim_interface *pim_ifp;

        switch (event) {
        case NB_EV_VALIDATE:
        case NB_EV_PREPARE:
        case NB_EV_ABORT:
                break;
        case NB_EV_APPLY:
                ifp = nb_running_get_entry(dnode, NULL, true);
                pim_ifp = ifp->info;

                if (!pim_ifp)
                        return NB_ERR_NOT_FOUND;
                
                pim_ifp->ucast_bsm_accept = false;

                break;
        }

        return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/active-active
 */
int lib_interface_pim_active_active_create(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
{
        struct interface *ifp;
        struct pim_interface *pim_ifp;

        switch (event) {
        case NB_EV_VALIDATE:
        case NB_EV_PREPARE:
        case NB_EV_ABORT:
                break;
        case NB_EV_APPLY:
                ifp = nb_running_get_entry(dnode, NULL, true);
                pim_ifp = ifp->info;

		if (PIM_DEBUG_MLAG)
                zlog_debug("Configuring PIM active-active on Interface: %s",
                           ifp->name);

		pim_if_configure_mlag_dualactive(pim_ifp);

                break;
        }

        return NB_OK;
}

int lib_interface_pim_active_active_destroy(enum nb_event event, const struct lyd_node *dnode)
{
        struct interface *ifp;
        struct pim_interface *pim_ifp;
                        
        switch (event) {
        case NB_EV_VALIDATE:
        case NB_EV_PREPARE:
        case NB_EV_ABORT:
                break;
        case NB_EV_APPLY:
                ifp = nb_running_get_entry(dnode, NULL, true);
                pim_ifp = ifp->info;

                zlog_debug("UnConfiguring PIM active-active on Interface: %s",
                           ifp->name);

                pim_if_unconfigure_mlag_dualactive(pim_ifp);
                break;
        }

        return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/address-family
 */
int lib_interface_pim_address_family_create(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int lib_interface_pim_address_family_destroy(enum nb_event event, const struct lyd_node *dnode)
{
	switch (event) {
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
 * XPath: /frr-interface:lib/interface/frr-pim:pim/address-family/use-source
 */
int lib_interface_pim_address_family_use_source_modify(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
{
	struct interface *ifp;
	struct ipaddr source_addr;
	int result;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_ABORT:
	case NB_EV_PREPARE:
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(dnode, NULL, true);
		yang_dnode_get_ip(&source_addr, dnode, NULL);

		result = interface_pim_use_src_cmd_worker(ifp, source_addr.ip._v4_addr);

		if (result != PIM_SUCCESS)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

int lib_interface_pim_address_family_use_source_destroy(enum nb_event event, const struct lyd_node *dnode)
{
        struct interface *ifp;
	struct in_addr source_addr = {INADDR_ANY};
	int result;

        switch (event) {
        case NB_EV_VALIDATE:
        case NB_EV_ABORT:
        case NB_EV_PREPARE:
        case NB_EV_APPLY:
                ifp = nb_running_get_entry(dnode, NULL, true);
                
                result = interface_pim_use_src_cmd_worker(ifp, source_addr);

                if (result != PIM_SUCCESS)
                        return NB_ERR_INCONSISTENCY;

                break;
        }

        return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/address-family/multicast-boundary-oil
 */
int lib_interface_pim_address_family_multicast_boundary_oil_modify(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
{
        struct interface *ifp;
        struct pim_interface *pim_ifp;
	const char *plist;

        switch (event) {
        case NB_EV_VALIDATE:
        case NB_EV_ABORT:
        case NB_EV_PREPARE:
        case NB_EV_APPLY:
                ifp = nb_running_get_entry(dnode, NULL, true);
                pim_ifp = ifp->info;

		if (!pim_ifp)
			return NB_ERR_NOT_FOUND;

		plist = yang_dnode_get_string(dnode, NULL);

	        if (pim_ifp->boundary_oil_plist)
                	XFREE(MTYPE_PIM_INTERFACE, pim_ifp->boundary_oil_plist);

        	pim_ifp->boundary_oil_plist =
                	XSTRDUP(MTYPE_PIM_INTERFACE, plist);

		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/address-family/multicast-boundary-oil
 */
int lib_interface_pim_address_family_multicast_boundary_oil_destroy(enum nb_event event, const struct lyd_node *dnode)
{
        struct interface *ifp;
        struct pim_interface *pim_ifp;

        switch (event) {
        case NB_EV_VALIDATE:
        case NB_EV_ABORT:
        case NB_EV_PREPARE:
        case NB_EV_APPLY:
                ifp = nb_running_get_entry(dnode, NULL, true);
                pim_ifp = ifp->info;

		if (!pim_ifp)
			return NB_ERR_NOT_FOUND;

     		if (pim_ifp->boundary_oil_plist)
                	XFREE(MTYPE_PIM_INTERFACE, pim_ifp->boundary_oil_plist);
       		break;
        }

        return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/address-family/mroute
 */
int lib_interface_pim_address_family_mroute_create(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
{
        return NB_OK;
}

int lib_interface_pim_address_family_mroute_destroy(enum nb_event event, const struct lyd_node *dnode)
{
        struct pim_instance *pim;
        struct pim_interface *pim_iifp;
        struct interface *iif;
        struct interface *oif;
        const char *oifname;
        struct ipaddr source_addr;
        struct ipaddr group_addr;

        switch (event) {
        case NB_EV_VALIDATE:
        case NB_EV_PREPARE:
        case NB_EV_ABORT:
                break;
        case NB_EV_APPLY:
                iif = nb_running_get_entry(dnode, NULL, true);
                pim_iifp = iif->info;

		if(!pim_iifp)
			return NB_ERR_NOT_FOUND;

                pim = pim_iifp->pim;

                oifname = yang_dnode_get_string(dnode, "./oif");
                oif = if_lookup_by_name(oifname, pim->vrf_id);

                if (!oif) {
                        flog_warn(EC_PIM_CONFIG, "%s: No such interface name %s\n", __func__, oifname);
                        return NB_ERR_INCONSISTENCY;
                }

                yang_dnode_get_ip(&source_addr, dnode, "./source-addr");
                yang_dnode_get_ip(&group_addr, dnode, "./group-addr");

                if (pim_static_del(pim, iif, oif, group_addr.ip._v4_addr, source_addr.ip._v4_addr)) {
                        flog_warn(EC_PIM_CONFIG, "Failed to delete static mroute");
                        return NB_ERR_INCONSISTENCY;
                }

                break;
        }

        return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/address-family/mroute/oif
 */
int lib_interface_pim_address_family_mroute_oif_modify(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
{
        struct pim_instance *pim;
        struct pim_interface *pim_iifp;
        struct interface *iif;
        struct interface *oif;
        const char *oifname;
        struct ipaddr source_addr;
        struct ipaddr group_addr;

        switch (event) {
        case NB_EV_VALIDATE:
        case NB_EV_PREPARE:
        case NB_EV_ABORT:
                break;
        case NB_EV_APPLY:

        	iif = nb_running_get_entry(dnode, NULL, true);
        	pim_iifp = iif->info;

		if(!pim_iifp)
			return NB_ERR_NOT_FOUND;

        	pim = pim_iifp->pim;

        	oifname = yang_dnode_get_string(dnode, NULL);
        	oif = if_lookup_by_name(oifname, pim->vrf_id);

        	if (!oif) {
                	flog_warn(EC_PIM_CONFIG, "%s: No such interface name %s\n", __func__, oifname);
                	return NB_ERR_INCONSISTENCY;
        	}

        	yang_dnode_get_ip(&source_addr, dnode, "../source-addr");
       		yang_dnode_get_ip(&group_addr, dnode, "../group-addr");

        	if (pim_static_add(pim, iif, oif, group_addr.ip._v4_addr, source_addr.ip._v4_addr)) {
                	flog_warn(EC_PIM_CONFIG, "Failed to add static mroute");
                	return NB_ERR_INCONSISTENCY;
        	}

		break;
	}
        
	return NB_OK;
}

int lib_interface_pim_address_family_mroute_oif_destroy(enum nb_event event, const struct lyd_node *dnode)
{
	switch (event) {
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/static-rp/rp-list
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_static_rp_rp_list_create(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
{
	switch (event) {
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
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_static_rp_rp_list_destroy(enum nb_event event, const struct lyd_node *dnode)
{
        struct pim_instance *pim;
        struct prefix group;
        struct ipaddr rp_addr;
        const char *plist;
        int result = 0;

        switch (event) {
        case NB_EV_VALIDATE:
        case NB_EV_PREPARE:
        case NB_EV_ABORT:
                break;
        case NB_EV_APPLY:
                pim = nb_running_get_entry(dnode, NULL, true);
                yang_dnode_get_ip(&rp_addr, dnode, "./rp-address");

		if (yang_dnode_get(dnode, "./group-list")) {
			yang_dnode_get_ipv4p(&group, dnode, "./group-list");
			result = pim_no_rp_cmd_worker(pim, rp_addr.ip._v4_addr, group, NULL);
		}

		else if (yang_dnode_get(dnode, "./prefix-list")) {
                	plist = yang_dnode_get_string(dnode, "./prefix-list");
			str2prefix("224.0.0.0/4", &group);
                	result = pim_no_rp_cmd_worker(pim, rp_addr.ip._v4_addr, group, plist);
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
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_static_rp_rp_list_group_list_create(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
{
        struct pim_instance *pim;
	struct prefix group;
	struct ipaddr rp_addr;
	int result;
	struct prefix temp;
 
        switch (event) {
        case NB_EV_VALIDATE:
		yang_dnode_get_ipv4p(&group, dnode, NULL);
		prefix_copy(&temp, &group);
		apply_mask(&temp);

		if (!prefix_same(&group, &temp))
			return NB_ERR_VALIDATION;

        case NB_EV_PREPARE:
        case NB_EV_ABORT:
                break;
        case NB_EV_APPLY:
                pim = nb_running_get_entry(dnode, NULL, true);
		yang_dnode_get_ip(&rp_addr, dnode, "../rp-address");
		yang_dnode_get_ipv4p(&group, dnode, NULL);

		result = pim_rp_cmd_worker(pim, rp_addr.ip._v4_addr, group, NULL);

		if (result)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/static-rp/rp-list/group-list
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_static_rp_rp_list_group_list_destroy(enum nb_event event, const struct lyd_node *dnode)
{
       struct pim_instance *pim;
        struct prefix group;
        struct ipaddr rp_addr;
        int result;
        
        switch (event) {
        case NB_EV_VALIDATE:
        case NB_EV_PREPARE:
        case NB_EV_ABORT:
                break;
        case NB_EV_APPLY:
                pim = nb_running_get_entry(dnode, NULL, true);
                yang_dnode_get_ip(&rp_addr, dnode, "../rp-address");
                yang_dnode_get_ipv4p(&group, dnode, NULL);

		result = pim_no_rp_cmd_worker(pim, rp_addr.ip._v4_addr, group, NULL);

		if (result)
			return NB_ERR_INCONSISTENCY;

		break;
	}

        return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/static-rp/rp-list/prefix-list
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_static_rp_rp_list_prefix_list_modify(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
{
        struct pim_instance *pim;
        struct prefix group;
        struct ipaddr rp_addr;
	const char *plist;
        int result;

        switch (event) {
        case NB_EV_VALIDATE:
        case NB_EV_PREPARE:
        case NB_EV_ABORT:
                break;
        case NB_EV_APPLY:
                pim = nb_running_get_entry(dnode, NULL, true);
                yang_dnode_get_ip(&rp_addr, dnode, "../rp-address");
		plist = yang_dnode_get_string(dnode, NULL);
		str2prefix("224.0.0.0/4", &group);
                result = pim_rp_cmd_worker(pim, rp_addr.ip._v4_addr, group, plist);
                
                if (result)
                        return NB_ERR_INCONSISTENCY;
                
                break;
        }
        
        return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/static-rp/rp-list/prefix-list
 */
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_static_rp_rp_list_prefix_list_destroy(enum nb_event event, const struct lyd_node *dnode)
{
        struct pim_instance *pim;
        struct prefix group;
        struct ipaddr rp_addr;
        const char *plist;
        int result;

        switch (event) {
        case NB_EV_VALIDATE:
        case NB_EV_PREPARE:
        case NB_EV_ABORT:
                break;
        case NB_EV_APPLY:
                pim = nb_running_get_entry(dnode, NULL, true);
                yang_dnode_get_ip(&rp_addr, dnode, "../rp-address");
                plist = yang_dnode_get_string(dnode, NULL);
                str2prefix("224.0.0.0/4", &group);
                result = pim_no_rp_cmd_worker(pim, rp_addr.ip._v4_addr, group, plist);

		if (result)
                        return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}


/*
 * XPath: /frr-interface:lib/interface/frr-igmp:igmp/igmp-enable
 */
int lib_interface_igmp_igmp_enable_modify(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
{
        struct interface *ifp;
        int ret = CMD_SUCCESS;
	bool igmp_enable;
	struct pim_interface *pim_ifp;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
                ifp = nb_running_get_entry(dnode, NULL, true);
		igmp_enable = yang_dnode_get_bool(dnode, NULL) ;
		if (igmp_enable)
                	ret = pim_cmd_igmp_start(ifp);

		else {
			pim_ifp = ifp->info;

                	if (!pim_ifp)
                        	return NB_ERR_NOT_FOUND;

	                PIM_IF_DONT_IGMP(pim_ifp->options);
	
        	        pim_if_membership_clear(ifp);

                	pim_if_addr_del_all_igmp(ifp);

	                if (!PIM_IF_TEST_PIM(pim_ifp->options)) {
        	                pim_if_delete(ifp);
                	}
			
               		if (ret != CMD_SUCCESS)
                		return NB_ERR_VALIDATION;
        	}

		break;
	}

	return NB_OK;
}

#if 0
/*
 * XPath: /frr-interface:lib/interface/frr-igmp:igmp/igmp-enable
 */
int lib_interface_igmp_igmp_enable_destroy(enum nb_event event, const struct lyd_node *dnode)
{
       struct interface *ifp;
        struct pim_interface *pim_ifp;
        
        switch (event) {
        case NB_EV_VALIDATE:
        case NB_EV_PREPARE:
        case NB_EV_ABORT:
        case NB_EV_APPLY:
		ifp = nb_running_get_entry(dnode, NULL, true);
                pim_ifp = ifp->info;

                if (!pim_ifp)
                        return NB_ERR_NOT_FOUND;
                PIM_IF_DONT_IGMP(pim_ifp->options);

                pim_if_membership_clear(ifp);

                pim_if_addr_del_all_igmp(ifp);

                if (!PIM_IF_TEST_PIM(pim_ifp->options)) {
                	pim_if_delete(ifp);
                }

                break;
        }
        
        return NB_OK;
}

#endif

/*
 * XPath: /frr-interface:lib/interface/frr-igmp:igmp/version
 */
int lib_interface_igmp_version_modify(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;
	int igmp_version, old_version = 0;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
                ifp = nb_running_get_entry(dnode, NULL, true);
                pim_ifp = ifp->info;

		if (!pim_ifp)
                        return NB_ERR_NOT_FOUND;

                igmp_version = yang_dnode_get_uint8(dnode, NULL);
                old_version = pim_ifp->igmp_version;
                pim_ifp->igmp_version = igmp_version;

                // Check if IGMP is Enabled otherwise, enable on interface
                if (!PIM_IF_TEST_IGMP(pim_ifp->options)) {
                        PIM_IF_DO_IGMP(pim_ifp->options);
                        pim_if_addr_add_all(ifp);
                        pim_if_membership_refresh(ifp);
                        old_version = igmp_version;
                        // avoid refreshing membership again.
                }

                /* Current and new version is different refresh existing
                 * membership. Going from 3 -> 2 or 2 -> 3. */
                if (old_version != igmp_version)
                        pim_if_membership_refresh(ifp);

                break;
        }

        return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-igmp:igmp/version
 */
int lib_interface_igmp_version_destroy(enum nb_event event, const struct lyd_node *dnode)
{
        struct interface *ifp;
        struct pim_interface *pim_ifp;

        switch (event) {
        case NB_EV_VALIDATE:
        case NB_EV_PREPARE:
        case NB_EV_ABORT:
        case NB_EV_APPLY:
		ifp = nb_running_get_entry(dnode, NULL, true);
		pim_ifp = ifp->info;

		if(pim_ifp == NULL)
			return NB_ERR_NOT_FOUND;

		pim_ifp->igmp_version = IGMP_DEFAULT_VERSION;

                break;
        }
        
        return NB_OK;
}

#define IGMP_QUERY_INTERVAL_MIN (1)
#define IGMP_QUERY_INTERVAL_MAX (1800)

/*
 * XPath: /frr-interface:lib/interface/frr-igmp:igmp/query-interval
 */
int lib_interface_igmp_query_interval_modify(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
{
        struct interface *ifp;
        struct pim_interface *pim_ifp;
        int query_interval;
        int query_interval_dsec;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(dnode, NULL, true);
		pim_ifp = ifp->info;

		if (!pim_ifp)
                        return NB_ERR_NOT_FOUND;

		query_interval = yang_dnode_get_uint16(dnode, NULL);
		query_interval_dsec = 10 * query_interval;
		
		if (query_interval_dsec <= pim_ifp->igmp_query_max_response_time_dsec) {
			flog_err(EC_LIB_NB_CB_CONFIG_APPLY,
				"Can't set general query interval %d dsec <= query max response time %d dsec.",
				query_interval_dsec, pim_ifp->igmp_query_max_response_time_dsec);
			return NB_ERR_INCONSISTENCY;
		}

		change_query_interval(pim_ifp, query_interval);

		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-igmp:igmp/query-max-response-time
 */
int lib_interface_igmp_query_max_response_time_modify(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;
	int query_max_response_time_dsec;
	int default_query_interval_dsec;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(dnode, NULL, true);
		pim_ifp = ifp->info;

		if (!pim_ifp)
                        return NB_ERR_NOT_FOUND;

		query_max_response_time_dsec = yang_dnode_get_uint8(dnode, NULL);
		default_query_interval_dsec = 10 * pim_ifp->igmp_default_query_interval;

		if (query_max_response_time_dsec >= default_query_interval_dsec) {
			flog_err(EC_LIB_NB_CB_CONFIG_VALIDATE,
				"Can't set query max response time %d sec >= general query interval %d sec\n",
				query_max_response_time_dsec,
				pim_ifp->igmp_default_query_interval);
			return NB_ERR_VALIDATION;
		}

		change_query_max_response_time(pim_ifp, query_max_response_time_dsec);

		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-igmp:igmp/last-member-query-interval
 */
int lib_interface_igmp_last_member_query_interval_modify(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;
	int last_member_query_interval;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
                ifp = nb_running_get_entry(dnode, NULL, true);

		pim_ifp = ifp->info;

		if (!pim_ifp)
			return NB_ERR_NOT_FOUND;

                last_member_query_interval = yang_dnode_get_uint8(dnode, NULL);

                pim_ifp->igmp_specific_query_max_response_time_dsec = last_member_query_interval;

		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-igmp:igmp/robustness-variable
 */
int lib_interface_igmp_robustness_variable_modify(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;
	int last_member_query_count;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
                ifp = nb_running_get_entry(dnode, NULL, true);
		pim_ifp = ifp->info;

		if (!pim_ifp)
			return NB_ERR_NOT_FOUND;

                last_member_query_count = yang_dnode_get_uint8(dnode, NULL);

                pim_ifp->igmp_last_member_query_count = last_member_query_count;

		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-igmp:igmp/address-family
 */
int lib_interface_igmp_address_family_create(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int lib_interface_igmp_address_family_destroy(enum nb_event event, const struct lyd_node *dnode)
{
	switch (event) {
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
int lib_interface_igmp_address_family_static_group_create(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
{

	struct interface *ifp;
	struct ipaddr source_addr;
	struct ipaddr group_addr;
	int result;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(dnode, NULL, true);
		yang_dnode_get_ip(&source_addr, dnode, "./source-addr");
		yang_dnode_get_ip(&group_addr, dnode, "./group-addr");

		result = pim_if_igmp_join_add(ifp, group_addr.ip._v4_addr, source_addr.ip._v4_addr);

		if (result) {
			char src_str[INET_ADDRSTRLEN];
			char grp_str[INET_ADDRSTRLEN];

			ipaddr2str(&source_addr, src_str, sizeof(src_str));
			ipaddr2str(&group_addr, grp_str, sizeof(grp_str));

			flog_warn(EC_PIM_CONFIG,
				"%s: Failure joining IGMP group %s %s on interface %s",
				__func__, src_str, grp_str, ifp->name);

			return NB_ERR_INCONSISTENCY;
		}
			
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-igmp:igmp/address-family/static-group
 */
int lib_interface_igmp_address_family_static_group_destroy(enum nb_event event, const struct lyd_node *dnode)
{
        struct interface *ifp;
        struct ipaddr source_addr;
        struct ipaddr group_addr;
        int result;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
                ifp = nb_running_get_entry(dnode, NULL, true);
		yang_dnode_get_ip(&source_addr, dnode, "./source-addr");
		yang_dnode_get_ip(&group_addr, dnode, "./group-addr");

                result = pim_if_igmp_join_del(ifp, group_addr.ip._v4_addr, source_addr.ip._v4_addr);

                if (result) {
			char src_str[INET_ADDRSTRLEN];
			char grp_str[INET_ADDRSTRLEN];

			ipaddr2str(&source_addr, src_str, sizeof(src_str));
			ipaddr2str(&group_addr, grp_str, sizeof(grp_str));

			flog_warn(EC_PIM_CONFIG,
				"%s: Failure leaving IGMP group %s %s on interface %s",
				__func__, src_str, grp_str, ifp->name);
			 
                        return NB_ERR_INCONSISTENCY;
                }

		break;
	}

	return NB_OK;
}
