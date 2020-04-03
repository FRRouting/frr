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
int pim_cmd_igmp_start(struct interface *ifp);
void pim_if_membership_refresh(struct interface *ifp);
void pim_if_membership_clear(struct interface *ifp);
void pim_ssm_range_reevaluate(struct pim_instance *pim);
int pim_cmd_interface_add(struct interface *ifp);
int pim_cmd_interface_delete(struct interface *ifp);
void detect_address_change(struct interface *ifp, int force_prim_as_any,
                           const char *caller);
int pim_cmd_spt_switchover(struct pim_instance *pim,
                        enum pim_spt_switchover spt,
                        const char *plist);
int pim_update_source_set(struct interface *ifp, struct in_addr source);
/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim
 */
int pim_instance_create(enum nb_event event, const struct lyd_node *dnode,
			 union nb_resource *resource)
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
int pim_instance_destroy(enum nb_event event, const struct lyd_node *dnode)
{

        return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/ecmp
 */
int pim_instance_ecmp_create(enum nb_event event,
			const struct lyd_node *dnode,
			union nb_resource *resource)
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
int pim_instance_ecmp_destroy(enum nb_event event,
                        const struct lyd_node *dnode)
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
int pim_instance_ecmp_rebalance_create(enum nb_event event,
			const struct lyd_node *dnode,
			union nb_resource *resource)
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

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/ecmp-rebalance
 */
int pim_instance_ecmp_rebalance_destroy(enum nb_event event,
                        const struct lyd_node *dnode)
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
int pim_instance_join_prune_interval_modify(enum nb_event event,
			const struct lyd_node *dnode,
			union nb_resource *resource)
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
int pim_instance_keep_alive_timer_modify(enum nb_event event,
				const struct lyd_node *dnode,
				union nb_resource *resource)
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
int pim_instance_rp_ka_timer_modify(enum nb_event event,
                        const struct lyd_node *dnode,
                        union nb_resource *resource)
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
int pim_instance_packets_modify(enum nb_event event,
			const struct lyd_node *dnode,
			union nb_resource *resource)
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
 * XPath: /frr-routing:routing/control-plane-protocols/frr-pim:pim/register-suppress-time
 */
int pim_instance_register_suppress_time_modify(enum nb_event event,
				const struct lyd_node *dnode,
				union nb_resource *resource)
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
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/
 */
int pim_instance_af_create(enum nb_event event,
                        const struct lyd_node *dnode,
                        union nb_resource *resource)
{
	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/
 */
int pim_instance_af_destroy(enum nb_event event,
                                const struct lyd_node *dnode)
{
	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/send-v6-secondary
 */
int pim_instance_send_v6_secondary_create(enum nb_event event,
			const struct lyd_node *dnode,
			union nb_resource *resource)
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

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/send-v6-secondary
 */
int pim_instance_send_v6_secondary_destroy(enum nb_event event,
                        const struct lyd_node *dnode)
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
int pim_instance_spt_switch_action_modify(enum nb_event event,
                        const struct lyd_node *dnode,
                        union nb_resource *resource)
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
int pim_instance_spt_switch_infinity_prefix_list_modify(enum nb_event event,
			const struct lyd_node *dnode,
			union nb_resource *resource)
{
	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/spt-switchover/spt-infinity-prefix-list
 */
int pim_instance_spt_switch_infinity_prefix_list_destroy(enum nb_event event,
                        const struct lyd_node *dnode)
{
	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/frr-pim:pim/address-family[address-family='%s']/ssm/prefix-list
 */
int pim_instance_ssm_prefix_list_modify(enum nb_event event,
				const struct lyd_node *dnode,
				union nb_resource *resource)
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
		result = pim_ssm_range_set(pim, pim->vrf_id, plist_name);
		if (result != PIM_SSM_ERR_NONE)
			return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/spt-switchover/spt-infinity-prefix-list
 */
int pim_instance_ssm_prefix_list_destroy(enum nb_event event,
                        const struct lyd_node *dnode)
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
                result = pim_ssm_range_set(pim, pim->vrf_id, NULL);
                if (result != PIM_SSM_ERR_NONE)
                        return NB_ERR_INCONSISTENCY;
		break;
	}

        return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/ssm-pingd/source-ip
 */
int pim_instance_ssm_pingd_source_ip_create(enum nb_event event,
			const struct lyd_node *dnode,
			union nb_resource *resource)
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
			/* TO BE DO
                	flog_warn(EC_LIB_NB_CB_CONFIG_APPLY, "Failure starting ssmpingd for source %s: %d\n",
                        	source_str, result);
			*/
            	    return NB_ERR_INCONSISTENCY;
        	}

                break;
        }

        return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/ssm-pingd/source-ip
 */
int pim_instance_ssm_pingd_source_ip_destroy(enum nb_event event,
                        const struct lyd_node *dnode)
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
			/*
                        flog_warn(EC_LIB_NB_CB_CONFIG_VALIDATE, "%% Failure stoping ssmpingd for source %s: %d\n",
                                source_str, result);
			*/
                    return NB_ERR_VALIDATION;
                }
                
                break;
        }
        
        return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/mspd/msdp-mesh-group/mesh-group-name
 */
int pim_instance_msdp_mesh_group_create(enum nb_event event,
                        const struct lyd_node *dnode,
                        union nb_resource *resource)
{
	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/mspd/msdp-mesh-group/mesh-group-name
 */
int pim_instance_msdp_mesh_group_destroy(enum nb_event event,
                        const struct lyd_node *dnode)
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
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/mspd/msdp-mesh-group/member-ip
 */
int pim_instance_msdp_mesh_group_member_create(enum nb_event event,
                        const struct lyd_node *dnode,
                        union nb_resource *resource)
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

		result = pim_msdp_mg_mbr_add(pim, mg, mbr_ip.ip._v4_addr);

		if (result != PIM_MSDP_ERR_NONE)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/mspd/msdp-mesh-group/member-ip
 */
int pim_instance_msdp_mesh_group_member_destroy(enum nb_event event,
                        const struct lyd_node *dnode)
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

        	result = pim_msdp_mg_mbr_del(pim, mg, mbr_ip.ip._v4_addr);

		if (result != PIM_MSDP_ERR_NONE)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}
	
/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/mspd/msdp-mesh-group/source-ip
 */
int pim_instance_msdp_mesh_group_source_modify(enum nb_event event,
                        const struct lyd_node *dnode,
                        union nb_resource *resource)
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

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/mspd/msdp-mesh-group/source-ip
 */
int pim_instance_msdp_mesh_group_source_destroy(enum nb_event event,
                        const struct lyd_node *dnode)
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
int pim_instance_msdp_peer_create(enum nb_event event,
                        const struct lyd_node *dnode,
                        union nb_resource *resource)
{
//	struct pim_instance *pim;

        switch (event) {
        case NB_EV_VALIDATE:
        case NB_EV_PREPARE:
        case NB_EV_ABORT:
                break;
        case NB_EV_APPLY:
//                pim = nb_running_get_entry(dnode, NULL, true);

		break;
	}		
	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp/msdp-peer/peer
 */
int pim_instance_msdp_peer_destroy(enum nb_event event,
                        const struct lyd_node *dnode)
{
	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp/msdp-peer/peer/source-ip
 */
int pim_instance_msdp_peer_ip_create(enum nb_event event,
                        const struct lyd_node *dnode,
                        union nb_resource *resource)
{
	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp/msdp-peer/peer/source-ip
 */
int pim_instance_msdp_peer_ip_destroy(enum nb_event event,
                        const struct lyd_node *dnode)
{
        return NB_OK;
}

#if 0
/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/mlag
 */

int pim_instance_mlag_create(enum nb_event event,
                        const struct lyd_node *dnode,
                        union nb_resource *resource)
{
        return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/mlag
 */
int pim_instance_mlag_destroy(enum nb_event event,
                        const struct lyd_node *dnode)
{
        return NB_OK;
}

#endif
/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/mlag
 */
void pim_instance_mlag_apply_finish(const struct lyd_node *dnode)
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
int pim_instance_mlag_peerlink_rif_modify(enum nb_event event,
                        const struct lyd_node *dnode,
                        union nb_resource *resource)
{
        return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/mlag/peerlink-rif
 */
int pim_instance_mlag_peerlink_rif_destroy(enum nb_event event,
                        const struct lyd_node *dnode)
{
        return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/mlag/reg-address
 */
int pim_instance_mlag_reg_address_modify(enum nb_event event,
                        const struct lyd_node *dnode,
                        union nb_resource *resource)
{
        return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/mlag/reg-address
 */
int pim_instance_mlag_reg_address_destroy(enum nb_event event,
                        const struct lyd_node *dnode)
{
        return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/mlag/my-role
 */
int pim_instance_mlag_my_role_modify(enum nb_event event,
                        const struct lyd_node *dnode,
                        union nb_resource *resource)
{
        return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/mlag/peer-state
 */
int pim_instance_mlag_peer_state_modify(enum nb_event event,
                        const struct lyd_node *dnode,
                        union nb_resource *resource)
{
        return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/register-accept-list
 */
int pim_instance_register_accept_list_modify(enum nb_event event,
                        const struct lyd_node *dnode,
                        union nb_resource *resource)
{
        return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/register-accept-list
 */
int pim_instance_register_accept_list_destroy(enum nb_event event,
                        const struct lyd_node *dnode)
{
        return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim
 */
int pim_interface_create(enum nb_event event,
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
 * XPath: /frr-interface:lib/interface/frr-pim:pim
 */
int pim_interface_destroy(enum nb_event event,
                        const struct lyd_node *dnode)
{
	struct interface *ifp;

        switch (event) {
        case NB_EV_VALIDATE:
        case NB_EV_PREPARE:
        case NB_EV_ABORT:
                break;
        case NB_EV_APPLY:
                ifp = nb_running_get_entry(dnode, NULL, true);
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
int pim_interface_dr_priority_modify(enum nb_event event,
                        const struct lyd_node *dnode,
                        union nb_resource *resource)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;
	uint32_t old_dr_prio;

	switch (event) {
	case NB_EV_VALIDATE:
		ifp = nb_running_get_entry(dnode, NULL, true);

		if (ifp == NULL)
			return NB_ERR_VALIDATION;

		pim_ifp = ifp->info;

		if (!pim_ifp) {
			flog_err(EC_LIB_NB_CB_CONFIG_VALIDATE,
                            "PIM not enabled on the interface %s",
                            ifp->name);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(dnode, NULL, true);
		pim_ifp = ifp->info;
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
int pim_interface_hello_interval_modify(enum nb_event event,
			const struct lyd_node *dnode,
			union nb_resource *resource)
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

		pim_ifp->pim_hello_period = yang_dnode_get_uint16(dnode, NULL);
		break;
	}

	return NB_OK;				
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/hello-holdtime
 */
int pim_interface_hello_holdtime_modify(enum nb_event event,
			const struct lyd_node *dnode,
			union nb_resource *resource)
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

		pim_ifp->pim_default_holdtime =
		    yang_dnode_get_uint16(dnode, NULL);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/hello-holdtime
 */
int pim_interface_hello_holdtime_destroy(enum nb_event event,
                        const struct lyd_node *dnode)
{
	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/bfd
 */
int pim_interface_bfd_create(enum nb_event event,
			const struct lyd_node *dnode,
			union nb_resource *resource)

{
	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/bfd
 */
int pim_interface_bfd_destroy(enum nb_event event,
                        const struct lyd_node *dnode)
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
void pim_interface_bfd_apply_finish(const struct lyd_node *dnode)
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
 * XPath: /frr-interface:lib/interface/frr-pim:pim/bfd
 */
int pim_interface_bfd_min_rx_interval_modify(enum nb_event event,
                                const struct lyd_node *dnode,
                                union nb_resource *resource)
{
	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/bfd
 */
int pim_interface_bfd_min_tx_interval_modify(enum nb_event event,
                                const struct lyd_node *dnode,
                                union nb_resource *resource)
{
        return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/bfd
 */
int pim_interface_bfd_detect_mult_modify(enum nb_event event,
                                const struct lyd_node *dnode,
                                union nb_resource *resource)
{
        return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/bsm
 */
int pim_interface_bsm_create(enum nb_event event,
			const struct lyd_node *dnode,
			union nb_resource *resource)
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

		pim_ifp->bsm_enable = true;

		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/bsm
 */
int pim_interface_bsm_destroy(enum nb_event event,
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
                pim_ifp = ifp->info;
                
                pim_ifp->bsm_enable = false;

                break;
        }

        return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/unicast-bsm
 */
int pim_interface_unicast_bsm_create(enum nb_event event,
			const struct lyd_node *dnode,
			union nb_resource *resource)
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

		pim_ifp->ucast_bsm_accept = true;

		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/unicast-bsm
 */
int pim_interface_unicast_bsm_destroy(enum nb_event event,
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
                pim_ifp = ifp->info;
                
                pim_ifp->ucast_bsm_accept = false;

                break;
        }

        return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/active-active
 */
int pim_interface_active_active_create(enum nb_event event,
                        const struct lyd_node *dnode,
                        union nb_resource *resource)
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

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/active-active
 */
int pim_interface_active_active_destroy(enum nb_event event,
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
int pim_interface_af_create(enum nb_event event,
                        const struct lyd_node *dnode,
                        union nb_resource *resource)
{
	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/address-family
 */
int pim_interface_af_destroy(enum nb_event event,
                        const struct lyd_node *dnode)
{
        return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/use-source
 */
int pim_interface_use_source_modify(enum nb_event event,
			const struct lyd_node *dnode,
			union nb_resource *resource)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;
	struct ipaddr source_addr;
	int result;

	switch (event) {
	case NB_EV_VALIDATE:
		ifp = nb_running_get_entry(dnode, NULL, true);

		if (ifp == NULL)
			return NB_ERR_VALIDATION;

		pim_ifp = ifp->info;

		if (!pim_ifp) {
			flog_warn(EC_LIB_NB_CB_CONFIG_VALIDATE,
				"Pim not enabled on this interface %s",
				ifp->name);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_ABORT:
	case NB_EV_PREPARE:
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(dnode, NULL, true);
		pim_ifp = ifp->info;
		yang_dnode_get_ip(&source_addr, dnode, NULL);

		result = pim_update_source_set(ifp, source_addr.ip._v4_addr);
		if (result != PIM_SUCCESS)
			return NB_ERR_INCONSISTENCY;
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/use-source
 */
int pim_interface_use_source_destroy(enum nb_event event,
                        const struct lyd_node *dnode)
{
        struct interface *ifp;
        struct pim_interface *pim_ifp;
	struct in_addr source_addr = {INADDR_ANY};
	int result;

        switch (event) {
        case NB_EV_VALIDATE:
                ifp = nb_running_get_entry(dnode, NULL, true);

                if (ifp == NULL)
                        return NB_ERR_VALIDATION;

                pim_ifp = ifp->info;

                if (!pim_ifp) {
                        flog_warn(EC_LIB_NB_CB_CONFIG_VALIDATE,
                                "Pim not enabled on this interface %s",
                                ifp->name);
                        return NB_OK;
                }
                break;
        case NB_EV_ABORT:
        case NB_EV_PREPARE:
        case NB_EV_APPLY:
                ifp = nb_running_get_entry(dnode, NULL, true);
                pim_ifp = ifp->info;
                
                result = pim_update_source_set(ifp, source_addr);
                if (result != PIM_SUCCESS)
                        return NB_ERR_INCONSISTENCY;
                break;
        }

        return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/address-family/multicast-boundary-oil
 */
int pim_interface_multicast_boundary_oil_modify(enum nb_event event,
                        const struct lyd_node *dnode,
                        union nb_resource *resource)
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
int pim_interface_multicast_boundary_oil_destroy(enum nb_event event,
                        const struct lyd_node *dnode)
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

     		if (pim_ifp->boundary_oil_plist)
                	XFREE(MTYPE_PIM_INTERFACE, pim_ifp->boundary_oil_plist);
       		break;
        }

        return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-igmp:igmp/igmp-enable
 */

int pim_interface_igmp_enable_modify(enum nb_event event,
			const struct lyd_node *dnode,
			union nb_resource *resource)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;
	int ret;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(dnode, NULL, true);

		if (ifp == NULL)
			break;

		if (yang_dnode_get_bool(dnode, NULL)) {
			ret = pim_cmd_igmp_start(ifp);
			if (ret != CMD_SUCCESS)
				return NB_ERR_VALIDATION;
		}
		else {
			pim_ifp = ifp->info;
			if (!pim_ifp)
				return NB_OK;
			PIM_IF_DONT_IGMP(pim_ifp->options);

			pim_if_membership_clear(ifp);

			pim_if_addr_del_all_igmp(ifp);

			if (!PIM_IF_TEST_PIM(pim_ifp->options)) {
				pim_if_delete(ifp);
			}
		}
		break;
	}

	return NB_OK;
}
/*
 * Xpath: /frr-interface:lib/interface/frr-igmp:igmp/vesrion
 */
int pim_interface_igmp_version_modify(enum nb_event event,
			const struct lyd_node *dnode,
			union nb_resource *resource)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;
	int igmp_version, old_version = 0;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(dnode, NULL, true);
		if (ifp == NULL)
			break;

		pim_ifp = ifp->info;

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

#define IGMP_QUERY_INTERVAL_MIN (1)
#define IGMP_QUERY_INTERVAL_MAX (1800)

/*
 * XPath: /frr-interface:lib/interface/frr-igmp:igmp/query-interval
 */
int pim_interface_query_interval_modify(enum nb_event event,
				const struct lyd_node *dnode,
				union nb_resource *resource)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;
	int query_interval;
	int query_interval_dsec;

	query_interval = yang_dnode_get_uint16(dnode, NULL);
	query_interval_dsec = 10 * query_interval;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(dnode, NULL, true);

		if (ifp == NULL) {
			break;
		}
	
		pim_ifp = ifp->info;

		/*
		 * It seems we don't need to check bounds since command.c does it
		 * already, but we verify them anyway for extra safety.
		 */
		if (query_interval < IGMP_QUERY_INTERVAL_MIN) {
			flog_err(EC_LIB_NB_CB_CONFIG_VALIDATE,
			    "General query interval %d lower than minimum %d",
			    query_interval, IGMP_QUERY_INTERVAL_MIN);
			return NB_ERR_VALIDATION;
		}

		if (query_interval > IGMP_QUERY_INTERVAL_MAX) {
			flog_err(EC_LIB_NB_CB_CONFIG_VALIDATE,
			    "General query interval %d higher than maximum %d",
			    query_interval, IGMP_QUERY_INTERVAL_MAX);
			return NB_ERR_VALIDATION;
		}

		if (query_interval_dsec <= pim_ifp->igmp_query_max_response_time_dsec) {
			flog_err(EC_LIB_NB_CB_CONFIG_VALIDATE,
			    "Can't set general query interval %d dsec <= query max response time %d dsec.",
			    query_interval_dsec, pim_ifp->igmp_query_max_response_time_dsec);
			return NB_ERR_VALIDATION;
		}

		change_query_interval(pim_ifp, query_interval);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-igmp:igmp/query-max-response-time
 */
int pim_interface_query_max_response_time_modify(enum nb_event event,
				const struct lyd_node *dnode,
				union nb_resource *resource)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;
	int query_max_response_time;

	query_max_response_time = yang_dnode_get_uint8(dnode, NULL);

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(dnode, NULL, true);

		if (ifp == NULL) {
			break;
		}	

		pim_ifp = ifp->info;

		if (query_max_response_time
		    >= pim_ifp->igmp_default_query_interval * 10) {
			flog_err(EC_LIB_NB_CB_CONFIG_VALIDATE,
			    "Can't set query max response time %d sec >= general query interval %d sec\n",
			    query_max_response_time,
			    pim_ifp->igmp_default_query_interval);
			return NB_ERR_VALIDATION;
		}

		change_query_max_response_time(pim_ifp, query_max_response_time);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-igmp:igmp/last-member-query-interval
 */
int pim_interface_last_member_query_interval_modify(enum nb_event event,
                                const struct lyd_node *dnode,
                                union nb_resource *resource)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;
	int last_member_query_interval;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(dnode, NULL, true);

		last_member_query_interval = yang_dnode_get_uint8(dnode, NULL);

		if (ifp == NULL) {
			break;
		}

		pim_ifp = ifp->info;

		pim_ifp->igmp_specific_query_max_response_time_dsec
                = last_member_query_interval;
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-igmp:igmp/robustness-variable
 */
int pim_interface_robustness_variable_modify(enum nb_event event,
                                const struct lyd_node *dnode,
                                union nb_resource *resource)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;
	int last_member_query_count;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(dnode, NULL, true);

		last_member_query_count = yang_dnode_get_uint8(dnode, NULL);

		if (ifp == NULL) {
			return NB_ERR_INCONSISTENCY;
		}

		pim_ifp = ifp->info;

		pim_ifp->igmp_last_member_query_count = last_member_query_count;
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/address-family/mroute
 */
int pim_interface_mroute_create(enum nb_event event,
                        const struct lyd_node *dnode,
                        union nb_resource *resource)
{
        return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/address-family/mroute
 */
int pim_interface_mroute_destroy(enum nb_event event,
                        const struct lyd_node *dnode)
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
                pim = pim_iifp->pim;

                oifname = yang_dnode_get_string(dnode, NULL);
                oif = if_lookup_by_name(oifname, pim->vrf_id);
                if (!oif) {
                        flog_warn(EC_PIM_CONFIG, "%s: No such interface name %s\n", __func__, oifname);
                        return NB_ERR_INCONSISTENCY;
                }

                yang_dnode_get_ip(&source_addr, dnode, "../source-addr");
                yang_dnode_get_ip(&group_addr, dnode, "../group-addr");

                if (pim_static_del(pim, iif, oif, group_addr.ip._v4_addr, source_addr.ip._v4_addr)) {
                        flog_warn(EC_PIM_CONFIG, "Failed to delete static mroute");
                        return NB_ERR_INCONSISTENCY;
                }

                break;
        }

        return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/address-family/mroute/interface
 */
int pim_interface_mroute_oif_modify(enum nb_event event,
                        const struct lyd_node *dnode,
                        union nb_resource *resource)
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

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/address-family/mroute/interface
 */
int pim_interface_mroute_oif_destroy(enum nb_event event,
                        const struct lyd_node *dnode)
{
        return NB_OK;
}

#if 0
/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/address-family/mroute/group-addr
 */
int pim_interface_mroute_group_addr_modify(enum nb_event event,
                        const struct lyd_node *dnode,
                        union nb_resource *resource)
{
        return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/address-family/mroute/group-addr
 */
int pim_interface_mroute_group_addr_destroy(enum nb_event event,
                        const struct lyd_node *dnode)
{
        return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/address-family/mroute/source-addr
 */
int pim_interface_mroute_source_addr_modify(enum nb_event event,
                        const struct lyd_node *dnode,
                        union nb_resource *resource)
{       
        return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-pim:pim/address-family/mroute/source-addr
 */
int pim_interface_mroute_source_addr_destroy(enum nb_event event,
                        const struct lyd_node *dnode)
{       
        return NB_OK;
}
#endif
/*
 * XPath: /frr-routing:routing/control-plane-protocols/frr-pim:pim/frr-pim-rp:rp/static-rp/rp
 */
int pim_instance_rp_list_create(enum nb_event event,
			const struct lyd_node *dnode,
			union nb_resource *resource)
{
	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/frr-pim:pim/frr-pim-rp:rp/static-rp/rp
 */
int pim_instance_rp_list_destroy(enum nb_event event,
			const struct lyd_node *dnode)
{
	return NB_OK;
}

int pim_instance_rp_group_list_create(enum nb_event event,
                        const struct lyd_node *dnode,
                        union nb_resource *resource)
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
		result = pim_rp_new(pim, rp_addr.ip._v4_addr, group, NULL, RP_SRC_STATIC);

		if (result)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}
int pim_instance_rp_group_list_destroy(enum nb_event event,
                        const struct lyd_node *dnode)
{
        return NB_OK;
}

int pim_instance_rp_prefix_list_modify(enum nb_event event,
                        const struct lyd_node *dnode,
                        union nb_resource *resource)
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
		result = str2prefix("224.0.0.0/4", &group);
                result = pim_rp_new(pim, rp_addr.ip._v4_addr, group, plist, RP_SRC_STATIC);
                
                if (result)
                        return NB_ERR_INCONSISTENCY;
                
                break;
        }
        
        return NB_OK;
}
#if 0
/*
 * XPath: /frr-routing:routing/control-plane-protocols/frr-pim:pim/frr-pim-rp:rp/static-rp/rpi-list/group-list
 */
int pim_instance_rp_group_list_create(enum nb_event event,
			const struct lyd_node *dnode,
			union nb_resource *resource)
{
	struct pim_instance *pim;
	const char *plist;
	struct prefix group;
	struct in_addr rp_addr;
	struct prefix temp;
	struct prefix group_all;

/*	str2prefix("224.0.0.0/4", &group_all);
	pim = pim_get_pim_instance(VRF_DEFAULT);
	yang_dnode_get_ipv4(&rp_addr, dnode, "../rp-address");
	yang_dnode_get_ipv4p(&group, dnode, NULL);
	plist = yang_dnode_get_string(dnode, "../prefix-list");

	if (plist[0] == '\0') {
		plist = NULL;
	}

*/
	switch (event) {
	case NB_EV_VALIDATE:
#if 0
		if (rp_addr.s_addr == INADDR_ANY ||
		    rp_addr.s_addr == INADDR_NONE) {
			flog_err(EC_LIB_NB_CB_CONFIG_VALIDATE,
				"Bad RP address specified");
			return NB_ERR_VALIDATION;
		}

		/*
		 * if group range is inconsistent address and mask
		 */
		prefix_copy(&temp, &group);
		apply_mask(&temp);

		if (!prefix_same(&group, &temp)) {
			flog_err(EC_LIB_NB_CB_CONFIG_VALIDATE,
			    "Inconsistent address and mask");
			return NB_ERR_VALIDATION;
		}

		/*
		 * if group is a non-multicast subnet
		 */
		if (!str2prefix("224.0.0.0/4", &group_all)) {
			flog_err(EC_LIB_NB_CB_CONFIG_VALIDATE,
				"Bad group address specified");
			return NB_ERR_VALIDATION;
		}
#endif
	case NB_EV_PREPARE:
		break;

	case NB_EV_APPLY:
		if (!pim_rp_new(pim, rp_addr, group, NULL, RP_SRC_STATIC))
			return NB_ERR_INCONSISTENCY;

	case NB_EV_ABORT:
                break;

	}

	return NB_OK;
}

int pim_instance_rp_group_list_destroy(enum nb_event event,
			const struct lyd_node *dnode)
{
	return NB_OK;
}


int pim_instance_rp_prefix_list_modify(enum nb_event event,
                        const struct lyd_node *dnode,
                        union nb_resource *resource)
{
	const char *plist;
	struct in_addr rp_addr;
	struct pim_instance *pim;
	struct prefix group_all;

/*	pim = nb_running_get_entry(dnode, NULL, true);
	yang_dnode_get_ipv4(&rp_addr, dnode, "../rp-address");
	plist = yang_dnode_get_string(dnode, NULL);
*/
	switch (event) {
	case NB_EV_VALIDATE:

	case NB_EV_PREPARE:
		break;

	case NB_EV_APPLY:
		str2prefix("224.0.0.0/4", &group_all);
		if (!pim_rp_new(pim, rp_addr, group_all, plist, RP_SRC_STATIC))
			return NB_ERR_INCONSISTENCY;

	case NB_EV_ABORT:
		break;
	}

	return NB_OK;
}
#endif
int pim_instance_rp_prefix_list_destroy(enum nb_event event,
                        const struct lyd_node *dnode)
{
	return NB_OK;
}

