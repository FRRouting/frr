/*
 * Copyright (C) 2019  Cumulus Networks, Inc.
 * Chirag Shah
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

#include "lib/log.h"
#include "lib/northbound.h"
#include "libfrr.h"
#include "lib/command.h"
#include "lib/routemap.h"
#include "zebra/zebra_nb.h"
#include "zebra/rib.h"
#include "zebra_nb.h"
#include "zebra/interface.h"
#include "zebra/connected.h"
#include "zebra/zebra_router.h"
#include "zebra/debug.h"
#include "zebra/zebra_vxlan_private.h"
#include "zebra/zebra_vxlan.h"

/*
 * XPath: /frr-zebra:zebra/mcast-rpf-lookup
 */
int zebra_mcast_rpf_lookup_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-zebra:zebra/ip-forwarding
 */
int zebra_ip_forwarding_modify(struct nb_cb_modify_args *args)
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

int zebra_ip_forwarding_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-zebra:zebra/ipv6-forwarding
 */
int zebra_ipv6_forwarding_modify(struct nb_cb_modify_args *args)
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

int zebra_ipv6_forwarding_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-zebra:zebra/workqueue-hold-timer
 */
int zebra_workqueue_hold_timer_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-zebra:zebra/zapi-packets
 */
int zebra_zapi_packets_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-zebra:zebra/import-kernel-table/table-id
 */
int zebra_import_kernel_table_table_id_modify(struct nb_cb_modify_args *args)
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

int zebra_import_kernel_table_table_id_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-zebra:zebra/import-kernel-table/distance
 */
int zebra_import_kernel_table_distance_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-zebra:zebra/import-kernel-table/route-map
 */
int zebra_import_kernel_table_route_map_modify(struct nb_cb_modify_args *args)
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

int zebra_import_kernel_table_route_map_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-zebra:zebra/allow-external-route-update
 */
int zebra_allow_external_route_update_create(struct nb_cb_create_args *args)
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

int zebra_allow_external_route_update_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-zebra:zebra/dplane-queue-limit
 */
int zebra_dplane_queue_limit_modify(struct nb_cb_modify_args *args)
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
 * XPath: /frr-zebra:zebra/debugs/debug-events
 */
int zebra_debugs_debug_events_modify(struct nb_cb_modify_args *args)
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

int zebra_debugs_debug_events_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-zebra:zebra/debugs/debug-zapi-send
 */
int zebra_debugs_debug_zapi_send_modify(struct nb_cb_modify_args *args)
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

int zebra_debugs_debug_zapi_send_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-zebra:zebra/debugs/debug-zapi-recv
 */
int zebra_debugs_debug_zapi_recv_modify(struct nb_cb_modify_args *args)
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

int zebra_debugs_debug_zapi_recv_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-zebra:zebra/debugs/debug-zapi-detail
 */
int zebra_debugs_debug_zapi_detail_modify(struct nb_cb_modify_args *args)
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

int zebra_debugs_debug_zapi_detail_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-zebra:zebra/debugs/debug-kernel
 */
int zebra_debugs_debug_kernel_modify(struct nb_cb_modify_args *args)
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

int zebra_debugs_debug_kernel_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-zebra:zebra/debugs/debug-kernel-msg-send
 */
int zebra_debugs_debug_kernel_msg_send_modify(struct nb_cb_modify_args *args)
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

int zebra_debugs_debug_kernel_msg_send_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-zebra:zebra/debugs/debug-kernel-msg-recv
 */
int zebra_debugs_debug_kernel_msg_recv_modify(struct nb_cb_modify_args *args)
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

int zebra_debugs_debug_kernel_msg_recv_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-zebra:zebra/debugs/debug-rib
 */
int zebra_debugs_debug_rib_modify(struct nb_cb_modify_args *args)
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

int zebra_debugs_debug_rib_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-zebra:zebra/debugs/debug-rib-detail
 */
int zebra_debugs_debug_rib_detail_modify(struct nb_cb_modify_args *args)
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

int zebra_debugs_debug_rib_detail_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-zebra:zebra/debugs/debug-fpm
 */
int zebra_debugs_debug_fpm_modify(struct nb_cb_modify_args *args)
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

int zebra_debugs_debug_fpm_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-zebra:zebra/debugs/debug-nht
 */
int zebra_debugs_debug_nht_modify(struct nb_cb_modify_args *args)
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

int zebra_debugs_debug_nht_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-zebra:zebra/debugs/debug-nht-detail
 */
int zebra_debugs_debug_nht_detail_modify(struct nb_cb_modify_args *args)
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

int zebra_debugs_debug_nht_detail_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-zebra:zebra/debugs/debug-mpls
 */
int zebra_debugs_debug_mpls_modify(struct nb_cb_modify_args *args)
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

int zebra_debugs_debug_mpls_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-zebra:zebra/debugs/debug-vxlan
 */
int zebra_debugs_debug_vxlan_modify(struct nb_cb_modify_args *args)
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

int zebra_debugs_debug_vxlan_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-zebra:zebra/debugs/debug-pw
 */
int zebra_debugs_debug_pw_modify(struct nb_cb_modify_args *args)
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

int zebra_debugs_debug_pw_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-zebra:zebra/debugs/debug-dplane
 */
int zebra_debugs_debug_dplane_modify(struct nb_cb_modify_args *args)
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

int zebra_debugs_debug_dplane_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-zebra:zebra/debugs/debug-dplane-detail
 */
int zebra_debugs_debug_dplane_detail_modify(struct nb_cb_modify_args *args)
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

int zebra_debugs_debug_dplane_detail_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-zebra:zebra/debugs/debug-mlag
 */
int zebra_debugs_debug_mlag_modify(struct nb_cb_modify_args *args)
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

int zebra_debugs_debug_mlag_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/ip-addrs
 */
int lib_interface_zebra_ip_addrs_create(struct nb_cb_create_args *args)
{
	struct interface *ifp;
	struct prefix prefix;
	char buf[PREFIX_STRLEN] = {0};

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	// addr_family = yang_dnode_get_enum(dnode, "./address-family");
	yang_dnode_get_prefix(&prefix, args->dnode, "./ip-prefix");
	apply_mask(&prefix);

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (prefix.family == AF_INET
		    && ipv4_martian(&prefix.u.prefix4)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				 "invalid address %pFX",
				 &prefix);
			return NB_ERR_VALIDATION;
		} else if (prefix.family == AF_INET6
			   && ipv6_martian(&prefix.u.prefix6)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				 "invalid address %pFX",
				 &prefix);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		if (prefix.family == AF_INET)
			if_ip_address_install(ifp, &prefix, NULL, NULL);
		else if (prefix.family == AF_INET6)
			if_ipv6_address_install(ifp, &prefix, NULL);

		break;
	}

	return NB_OK;
}

int lib_interface_zebra_ip_addrs_destroy(struct nb_cb_destroy_args *args)
{
	struct interface *ifp;
	struct prefix prefix;
	struct connected *ifc;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	yang_dnode_get_prefix(&prefix, args->dnode, "./ip-prefix");
	apply_mask(&prefix);

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (prefix.family == AF_INET) {
			/* Check current interface address. */
			ifc = connected_check_ptp(ifp, &prefix, NULL);
			if (!ifc) {
				snprintf(args->errmsg, args->errmsg_len,
					 "interface %s Can't find address\n",
					 ifp->name);
				return NB_ERR_VALIDATION;
			}
		} else if (prefix.family == AF_INET6) {
			/* Check current interface address. */
			ifc = connected_check(ifp, &prefix);
			if (!ifc) {
				snprintf(args->errmsg, args->errmsg_len,
					 "interface can't find address %s",
					 ifp->name);
				return NB_ERR_VALIDATION;
			}
		} else
			return NB_ERR_VALIDATION;

		/* This is not configured address. */
		if (!CHECK_FLAG(ifc->conf, ZEBRA_IFC_CONFIGURED)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "interface %s not configured", ifp->name);
			return NB_ERR_VALIDATION;
		}

		/* This is not real address or interface is not active. */
		if (!CHECK_FLAG(ifc->conf, ZEBRA_IFC_QUEUED)
		    || !CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE)) {
			listnode_delete(ifp->connected, ifc);
			connected_free(&ifc);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		if_ip_address_uinstall(ifp, &prefix);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/ip-addrs/label
 */
int lib_interface_zebra_ip_addrs_label_modify(struct nb_cb_modify_args *args)
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

int lib_interface_zebra_ip_addrs_label_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/ip-addrs/ip4-peer
 */
int lib_interface_zebra_ip_addrs_ip4_peer_modify(struct nb_cb_modify_args *args)
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

int lib_interface_zebra_ip_addrs_ip4_peer_destroy(
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
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/multicast
 */
int lib_interface_zebra_multicast_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	struct interface *ifp;

	ifp = nb_running_get_entry(args->dnode, NULL, true);

	if_multicast_set(ifp);

	return NB_OK;
}

int lib_interface_zebra_multicast_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	struct interface *ifp;

	ifp = nb_running_get_entry(args->dnode, NULL, true);

	if_multicast_unset(ifp);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/link-detect
 */
int lib_interface_zebra_link_detect_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	struct interface *ifp;
	bool link_detect;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	link_detect = yang_dnode_get_bool(args->dnode, "./link-detect");

	if_linkdetect(ifp, link_detect);

	return NB_OK;
}

int lib_interface_zebra_link_detect_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	struct interface *ifp;
	bool link_detect;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	link_detect = yang_dnode_get_bool(args->dnode, "./link-detect");

	if_linkdetect(ifp, link_detect);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/shutdown
 */
int lib_interface_zebra_shutdown_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;

	ifp = nb_running_get_entry(args->dnode, NULL, true);

	if_shutdown(ifp);

	return NB_OK;
}

int lib_interface_zebra_shutdown_destroy(struct nb_cb_destroy_args *args)
{
	struct interface *ifp;

	ifp = nb_running_get_entry(args->dnode, NULL, true);

	if_no_shutdown(ifp);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/bandwidth
 */
int lib_interface_zebra_bandwidth_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	struct interface *ifp;
	uint32_t bandwidth;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	bandwidth = yang_dnode_get_uint32(args->dnode, "./bandwidth");

	ifp->bandwidth = bandwidth;

	/* force protocols to recalculate routes due to cost change */
	if (if_is_operative(ifp))
		zebra_interface_up_update(ifp);

	return NB_OK;
}

int lib_interface_zebra_bandwidth_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	struct interface *ifp;

	ifp = nb_running_get_entry(args->dnode, NULL, true);

	ifp->bandwidth = 0;

	/* force protocols to recalculate routes due to cost change */
	if (if_is_operative(ifp))
		zebra_interface_up_update(ifp);

	return NB_OK;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib
 */
int lib_vrf_zebra_ribs_rib_create(struct nb_cb_create_args *args)
{
	struct vrf *vrf;
	afi_t afi;
	safi_t safi;
	struct zebra_vrf *zvrf;
	struct zebra_router_table *zrt;
	uint32_t table_id;
	const char *afi_safi_name;

	vrf = nb_running_get_entry(args->dnode, NULL, false);
	zvrf = vrf_info_lookup(vrf->vrf_id);
	table_id = yang_dnode_get_uint32(args->dnode, "./table-id");
	if (!table_id)
		table_id = zvrf->table_id;

	afi_safi_name = yang_dnode_get_string(args->dnode, "./afi-safi-name");
	yang_afi_safi_identity2value(afi_safi_name, &afi, &safi);

	zrt = zebra_router_find_zrt(zvrf, table_id, afi, safi);

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (!zrt) {
			snprintf(args->errmsg, args->errmsg_len,
				 "vrf %s table is not found.", vrf->name);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:

		nb_running_set_entry(args->dnode, zrt);

		break;
	}

	return NB_OK;
}

int lib_vrf_zebra_ribs_rib_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	nb_running_unset_entry(args->dnode);

	return NB_OK;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:zebra/l3vni-id
 */
int lib_vrf_zebra_l3vni_id_modify(struct nb_cb_modify_args *args)
{
	struct vrf *vrf;
	struct zebra_vrf *zvrf;
	vni_t vni = 0;
	zebra_l3vni_t *zl3vni = NULL;
	struct zebra_vrf *zvrf_evpn = NULL;
	char err[ERR_STR_SZ];
	bool pfx_only = false;
	const struct lyd_node *pn_dnode;
	const char *vrfname;

	switch (args->event) {
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_VALIDATE:
		zvrf_evpn = zebra_vrf_get_evpn();
		if (!zvrf_evpn)
			return NB_ERR_VALIDATION;

		vni = yang_dnode_get_uint32(args->dnode, NULL);
		/* Get vrf info from parent node, reject configuration
		 * if zebra vrf already mapped to different vni id.
		 */
		pn_dnode = yang_dnode_get_parent(args->dnode, "vrf");
		if (pn_dnode) {
			vrfname = yang_dnode_get_string(pn_dnode, "./name");
			vrf = vrf_lookup_by_name(vrfname);
			zvrf = zebra_vrf_lookup_by_id(vrf->vrf_id);
			if (zvrf->l3vni && zvrf->l3vni != vni) {
				zlog_debug(
					"vni %u cannot be configured as vni %u is already configured under the vrf",
					vni, zvrf->l3vni);
				return NB_ERR_VALIDATION;
			}
		}

		/* Check if this VNI is already present in the system */
		zl3vni = zl3vni_lookup(vni);
		if (zl3vni) {
			if (IS_ZEBRA_DEBUG_VXLAN)
				zlog_debug(
					"VNI %u is already configured as L3-VNI",
					vni);
			return NB_ERR_VALIDATION;
		}

		break;
	case NB_EV_APPLY:

		vrf = nb_running_get_entry(args->dnode, NULL, true);
		zvrf = zebra_vrf_lookup_by_id(vrf->vrf_id);
		vni = yang_dnode_get_uint32(args->dnode, NULL);
		/* Note: This covers lib_vrf_zebra_prefix_only_modify() config
		 * along with l3vni config
		 */
		pfx_only = yang_dnode_get_bool(args->dnode, "../prefix-only");

		if (zebra_vxlan_process_vrf_vni_cmd(zvrf, vni, err, ERR_STR_SZ,
						    pfx_only ? 1 : 0, 1)
		    != 0) {
			if (IS_ZEBRA_DEBUG_VXLAN)
				zlog_debug(
					"vrf vni %u mapping failed with error: %s",
					vni, err);
			return NB_ERR;
		}

		/* Mark as having FRR configuration */
		vrf_set_user_cfged(vrf);

		break;
	}

	return NB_OK;
}

int lib_vrf_zebra_l3vni_id_destroy(struct nb_cb_destroy_args *args)
{
	struct vrf *vrf;
	struct zebra_vrf *zvrf;
	vni_t vni = 0;
	char err[ERR_STR_SZ];
	uint8_t filter = 0;

	switch (args->event) {
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_VALIDATE:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		zvrf = zebra_vrf_lookup_by_id(vrf->vrf_id);
		vni = yang_dnode_get_uint32(args->dnode, NULL);

		if (!zl3vni_lookup(vni))
			return NB_OK;

		if (zvrf->l3vni != vni)
			return NB_ERR;

		if (is_l3vni_for_prefix_routes_only(zvrf->l3vni))
			filter = 1;

		if (zebra_vxlan_process_vrf_vni_cmd(zvrf, vni, err, ERR_STR_SZ,
						    filter, 0)
		    != 0) {
			if (IS_ZEBRA_DEBUG_VXLAN)
				zlog_debug(
					"vrf vni %u unmapping failed with error: %s",
					vni, err);
			return NB_ERR;
		}

		/* If no other FRR config for this VRF, mark accordingly. */
		if (!zebra_vrf_has_config(zvrf))
			vrf_reset_user_cfged(vrf);

		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:zebra/prefix-only
 */
int lib_vrf_zebra_prefix_only_modify(struct nb_cb_modify_args *args)
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
 * XPath:
 * /frr-route-map:lib/route-map/entry/match-condition/frr-zebra:ipv4-prefix-length
 */
int lib_route_map_entry_match_condition_ipv4_prefix_length_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *length;
	int condition, rv;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	length = yang_dnode_get_string(args->dnode, NULL);
	condition =
		yang_dnode_get_enum(args->dnode, "../frr-route-map:condition");

	/* Set destroy information. */
	switch (condition) {
	case 100: /* ipv4-prefix-length */
		rhc->rhc_rule = "ip address prefix-len";
		break;

	case 102: /* ipv4-next-hop-prefix-length */
		rhc->rhc_rule = "ip next-hop prefix-len";
		break;
	}
	rhc->rhc_mhook = generic_match_delete;
	rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

	rv = generic_match_add(NULL, rhc->rhc_rmi, rhc->rhc_rule, length,
			       RMAP_EVENT_MATCH_ADDED);
	if (rv != CMD_SUCCESS) {
		rhc->rhc_mhook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

int lib_route_map_entry_match_condition_ipv4_prefix_length_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_match_destroy(args);
}

/*
 * XPath:
 * /frr-route-map:lib/route-map/entry/match-condition/frr-zebra:ipv6-prefix-length
 */
int lib_route_map_entry_match_condition_ipv6_prefix_length_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *length;
	int rv;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	length = yang_dnode_get_string(args->dnode, NULL);

	/* Set destroy information. */
	rhc->rhc_mhook = generic_match_delete;
	rhc->rhc_rule = "ipv6 address prefix-len";
	rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

	rv = generic_match_add(NULL, rhc->rhc_rmi, "ipv6 address prefix-len",
			       length, RMAP_EVENT_MATCH_ADDED);
	if (rv != CMD_SUCCESS) {
		rhc->rhc_mhook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

int lib_route_map_entry_match_condition_ipv6_prefix_length_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_match_destroy(args);
}

/*
 * XPath:
 * /frr-route-map:lib/route-map/entry/match-condition/frr-zebra:source-protocol
 */
int lib_route_map_entry_match_condition_source_protocol_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *type;
	int rv;

	switch (args->event) {
	case NB_EV_VALIDATE:
		type = yang_dnode_get_string(args->dnode, NULL);
		if (proto_name2num(type) == -1) {
			snprintf(args->errmsg, args->errmsg_len,
				 "invalid protocol: %s", type);
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		/* NOTHING */
		break;
	}

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	type = yang_dnode_get_string(args->dnode, NULL);

	/* Set destroy information. */
	rhc->rhc_mhook = generic_match_delete;
	rhc->rhc_rule = "source-protocol";
	rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

	rv = generic_match_add(NULL, rhc->rhc_rmi, "source-protocol", type,
			       RMAP_EVENT_MATCH_ADDED);
	if (rv != CMD_SUCCESS) {
		rhc->rhc_mhook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

int lib_route_map_entry_match_condition_source_protocol_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_match_destroy(args);
}

/*
 * XPath:
 * /frr-route-map:lib/route-map/entry/match-condition/frr-zebra:source-instance
 */
int lib_route_map_entry_match_condition_source_instance_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	const char *type;
	int rv;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	type = yang_dnode_get_string(args->dnode, NULL);

	/* Set destroy information. */
	rhc->rhc_mhook = generic_match_delete;
	rhc->rhc_rule = "source-instance";
	rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

	rv = generic_match_add(NULL, rhc->rhc_rmi, "source-instance", type,
			       RMAP_EVENT_MATCH_ADDED);
	if (rv != CMD_SUCCESS) {
		rhc->rhc_mhook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

int lib_route_map_entry_match_condition_source_instance_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_match_destroy(args);
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/set-action/frr-zebra:source-v4
 */
int lib_route_map_entry_set_action_source_v4_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	struct interface *pif = NULL;
	const char *source;
	struct vrf *vrf;
	struct prefix p;
	int rv;

	switch (args->event) {
	case NB_EV_VALIDATE:
		memset(&p, 0, sizeof(p));
		yang_dnode_get_ipv4p(&p, args->dnode, NULL);
		if (zebra_check_addr(&p) == 0) {
			snprintf(args->errmsg, args->errmsg_len,
				 "invalid IPv4 address: %s",
				 yang_dnode_get_string(args->dnode, NULL));
			return NB_ERR_VALIDATION;
		}

		RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
			pif = if_lookup_exact_address(&p.u.prefix4, AF_INET,
						      vrf->vrf_id);
			if (pif != NULL)
				break;
		}
		if (pif == NULL) {
			snprintf(args->errmsg, args->errmsg_len,
				 "is not a local adddress: %s",
				 yang_dnode_get_string(args->dnode, NULL));
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		/* NOTHING */
		break;
	}

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	source = yang_dnode_get_string(args->dnode, NULL);

	/* Set destroy information. */
	rhc->rhc_shook = generic_set_delete;
	rhc->rhc_rule = "src";

	rv = generic_set_add(NULL, rhc->rhc_rmi, "src", source);
	if (rv != CMD_SUCCESS) {
		rhc->rhc_shook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

int lib_route_map_entry_set_action_source_v4_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_set_destroy(args);
}

/*
 * XPath: /frr-route-map:lib/route-map/entry/set-action/frr-zebra:source-v6
 */
int lib_route_map_entry_set_action_source_v6_modify(
	struct nb_cb_modify_args *args)
{
	struct routemap_hook_context *rhc;
	struct interface *pif = NULL;
	const char *source;
	struct vrf *vrf;
	struct prefix p;
	int rv;

	switch (args->event) {
	case NB_EV_VALIDATE:
		memset(&p, 0, sizeof(p));
		yang_dnode_get_ipv6p(&p, args->dnode, NULL);
		if (zebra_check_addr(&p) == 0) {
			snprintf(args->errmsg, args->errmsg_len,
				 "invalid IPv6 address: %s",
				 yang_dnode_get_string(args->dnode, NULL));
			return NB_ERR_VALIDATION;
		}

		RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
			pif = if_lookup_exact_address(&p.u.prefix6, AF_INET6,
						      vrf->vrf_id);
			if (pif != NULL)
				break;
		}
		if (pif == NULL) {
			snprintf(args->errmsg, args->errmsg_len,
				 "is not a local adddress: %s",
				 yang_dnode_get_string(args->dnode, NULL));
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		/* NOTHING */
		break;
	}

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	source = yang_dnode_get_string(args->dnode, NULL);

	/* Set destroy information. */
	rhc->rhc_shook = generic_set_delete;
	rhc->rhc_rule = "src";

	rv = generic_set_add(NULL, rhc->rhc_rmi, "src", source);
	if (rv != CMD_SUCCESS) {
		rhc->rhc_shook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

int lib_route_map_entry_set_action_source_v6_destroy(
	struct nb_cb_destroy_args *args)
{
	return lib_route_map_entry_set_destroy(args);
}
