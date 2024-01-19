// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2019  Cumulus Networks, Inc.
 * Chirag Shah
 */

#include <zebra.h>

#include "lib/admin_group.h"
#include "lib/affinitymap.h"
#include "lib/log.h"
#include "lib/northbound.h"
#include "lib/printfrr.h"
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
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/ipv4-addrs
 */
int lib_interface_zebra_ipv4_addrs_create(struct nb_cb_create_args *args)
{
	struct interface *ifp;
	struct prefix p;
	const char *label = NULL;

	p.family = AF_INET;
	yang_dnode_get_ipv4(&p.u.prefix4, args->dnode, "ip");
	p.prefixlen = yang_dnode_get_uint8(args->dnode, "prefix-length");

	if (yang_dnode_exists(args->dnode, "label"))
		label = yang_dnode_get_string(args->dnode, "label");

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (ipv4_martian(&p.u.prefix4)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "invalid address %pFX", &p);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		if_ip_address_install(ifp, &p, label, NULL);

		/* set something for checking on label modify */
		nb_running_set_entry(args->dnode, (void *)0x1);
		break;
	}

	return NB_OK;
}

int lib_interface_zebra_ipv4_addrs_destroy(struct nb_cb_destroy_args *args)
{
	struct interface *ifp;
	struct prefix p;

	p.family = AF_INET;
	yang_dnode_get_ipv4(&p.u.prefix4, args->dnode, "ip");
	p.prefixlen = yang_dnode_get_uint8(args->dnode, "prefix-length");

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		nb_running_unset_entry(args->dnode);

		ifp = nb_running_get_entry(args->dnode, NULL, false);
		if_ip_address_uninstall(ifp, &p, NULL);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/ipv4-addrs/label
 */
int lib_interface_zebra_ipv4_addrs_label_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		if (nb_running_get_entry_non_rec(lyd_parent(args->dnode), NULL,
						 false)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Changing label is not allowed");
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

int lib_interface_zebra_ipv4_addrs_label_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len,
			 "Removing label is not allowed");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/ipv4-p2p-addrs
 */
int lib_interface_zebra_ipv4_p2p_addrs_create(struct nb_cb_create_args *args)
{
	struct interface *ifp;
	struct prefix p, pp;
	const char *label = NULL;

	p.family = AF_INET;
	yang_dnode_get_ipv4(&p.u.prefix4, args->dnode, "ip");
	p.prefixlen = 32;

	pp.family = AF_INET;
	yang_dnode_get_ipv4(&pp.u.prefix4, args->dnode, "peer-ip");
	pp.prefixlen = yang_dnode_get_uint8(args->dnode, "peer-prefix-length");

	if (yang_dnode_exists(args->dnode, "label"))
		label = yang_dnode_get_string(args->dnode, "label");

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (ipv4_martian(&p.u.prefix4)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "invalid address %pFX", &p);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		if_ip_address_install(ifp, &p, label, &pp);

		/* set something for checking on label modify */
		nb_running_set_entry(args->dnode, (void *)0x1);
		break;
	}

	return NB_OK;
}

int lib_interface_zebra_ipv4_p2p_addrs_destroy(struct nb_cb_destroy_args *args)
{
	struct interface *ifp;
	struct prefix p, pp;

	p.family = AF_INET;
	yang_dnode_get_ipv4(&p.u.prefix4, args->dnode, "ip");
	p.prefixlen = 32;

	pp.family = AF_INET;
	yang_dnode_get_ipv4(&pp.u.prefix4, args->dnode, "peer-ip");
	pp.prefixlen = yang_dnode_get_uint8(args->dnode, "peer-prefix-length");

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		nb_running_unset_entry(args->dnode);

		ifp = nb_running_get_entry(args->dnode, NULL, false);
		if_ip_address_uninstall(ifp, &p, &pp);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/ipv4-p2p-addrs/label
 */
int lib_interface_zebra_ipv4_p2p_addrs_label_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		if (nb_running_get_entry_non_rec(lyd_parent(args->dnode), NULL,
						 false)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Changing label is not allowed");
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

int lib_interface_zebra_ipv4_p2p_addrs_label_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len,
			 "Removing label is not allowed");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/ipv6-addrs
 */
int lib_interface_zebra_ipv6_addrs_create(struct nb_cb_create_args *args)
{
	struct interface *ifp;
	struct prefix p;

	p.family = AF_INET6;
	yang_dnode_get_ipv6(&p.u.prefix6, args->dnode, "ip");
	p.prefixlen = yang_dnode_get_uint8(args->dnode, "prefix-length");

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (ipv6_martian(&p.u.prefix6)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "invalid address %pFX", &p);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		if_ipv6_address_install(ifp, &p);
		break;
	}

	return NB_OK;
}

int lib_interface_zebra_ipv6_addrs_destroy(struct nb_cb_destroy_args *args)
{
	struct interface *ifp;
	struct prefix p;

	p.family = AF_INET6;
	yang_dnode_get_ipv6(&p.u.prefix6, args->dnode, "ip");
	p.prefixlen = yang_dnode_get_uint8(args->dnode, "prefix-length");

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, false);
		if_ipv6_address_uninstall(ifp, &p);
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
	bool multicast = yang_dnode_get_bool(args->dnode, NULL);

	ifp = nb_running_get_entry(args->dnode, NULL, true);

	if (multicast)
		if_multicast_set(ifp);
	else
		if_multicast_unset(ifp);

	return NB_OK;
}

int lib_interface_zebra_multicast_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	struct interface *ifp;
	struct zebra_if *zif;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	zif = ifp->info;

	zif->multicast = IF_ZEBRA_DATA_UNSPEC;

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
	link_detect = yang_dnode_get_bool(args->dnode, NULL);

	if_linkdetect(ifp, link_detect);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/enabled
 */
int lib_interface_zebra_enabled_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	struct interface *ifp;
	bool enabled;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	enabled = yang_dnode_get_bool(args->dnode, NULL);

	if (enabled)
		if_no_shutdown(ifp);
	else
		if_shutdown(ifp);

	return NB_OK;
}

int lib_interface_zebra_enabled_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	struct interface *ifp;
	struct zebra_if *zif;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	zif = ifp->info;

	zif->shutdown = IF_ZEBRA_DATA_UNSPEC;

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/mpls
 */
int lib_interface_zebra_mpls_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	bool mpls;
	struct zebra_if *zif;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	zif = ifp->info;
	mpls = yang_dnode_get_bool(args->dnode, NULL);

	if (mpls)
		zif->mpls_config = IF_ZEBRA_DATA_ON;
	else
		zif->mpls_config = IF_ZEBRA_DATA_OFF;

	dplane_intf_mpls_modify_state(ifp, mpls);

	return NB_OK;
}

int lib_interface_zebra_mpls_destroy(struct nb_cb_destroy_args *args)
{
	struct interface *ifp;
	struct zebra_if *zif;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	zif = ifp->info;

	zif->mpls_config = IF_ZEBRA_DATA_UNSPEC;

	/* keep the state as it is */

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
	bandwidth = yang_dnode_get_uint32(args->dnode, NULL);

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
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/link-params
 */
int lib_interface_zebra_link_params_create(struct nb_cb_create_args *args)
{
	struct interface *ifp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	if_link_params_enable(ifp);
	if (if_is_operative(ifp))
		zebra_interface_parameters_update(ifp);

	return NB_OK;
}

int lib_interface_zebra_link_params_destroy(struct nb_cb_destroy_args *args)
{
	struct interface *ifp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	if_link_params_free(ifp);
	if (if_is_operative(ifp))
		zebra_interface_parameters_update(ifp);

	return NB_OK;
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-zebra:zebra/link-params/legacy-admin-group
 */
int lib_interface_zebra_legacy_admin_group_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct if_link_params *iflp;
	uint32_t admin_group_value;

	admin_group_value = yang_dnode_get_uint32(args->dnode, ".");

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		iflp = if_link_params_get(ifp);

		iflp->admin_grp = admin_group_value;
		SET_PARAM(iflp, LP_ADM_GRP);

		admin_group_clear(&iflp->ext_admin_grp);
		UNSET_PARAM(iflp, LP_EXTEND_ADM_GRP);

		if (if_is_operative(ifp))
			zebra_interface_parameters_update(ifp);
		break;
	}
	return NB_OK;
}

int lib_interface_zebra_legacy_admin_group_destroy(
	struct nb_cb_destroy_args *args)
{
	struct interface *ifp;
	struct if_link_params *iflp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		iflp = if_link_params_get(ifp);

		iflp->admin_grp = 0;
		UNSET_PARAM(iflp, LP_ADM_GRP);

		if (if_is_operative(ifp))
			zebra_interface_parameters_update(ifp);
		break;
	}
	return NB_OK;
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-zebra:zebra/link-params/affinities/affinity
 */
int lib_interface_zebra_affinity_create(struct nb_cb_create_args *args)
{
	struct interface *ifp;
	const char *affname;
	struct if_link_params *iflp;
	struct affinity_map *affmap;
	enum affinity_mode affinity_mode;

	affname = yang_dnode_get_string(args->dnode, ".");
	affinity_mode = yang_dnode_get_enum(args->dnode, "../../affinity-mode");

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		iflp = if_link_params_get(ifp);
		affmap = affinity_map_get(affname);

		if (affmap->bit_position < 32 &&
		    (affinity_mode == AFFINITY_MODE_STANDARD ||
		     affinity_mode == AFFINITY_MODE_BOTH)) {
			iflp->admin_grp |= 1 << affmap->bit_position;
			SET_PARAM(iflp, LP_ADM_GRP);
		}
		if (affinity_mode == AFFINITY_MODE_EXTENDED ||
		    affinity_mode == AFFINITY_MODE_BOTH) {
			admin_group_set(&iflp->ext_admin_grp,
					affmap->bit_position);
			SET_PARAM(iflp, LP_EXTEND_ADM_GRP);
		}

		if (if_is_operative(ifp))
			zebra_interface_parameters_update(ifp);
		break;
	}
	return NB_OK;
}

int lib_interface_zebra_affinity_destroy(struct nb_cb_destroy_args *args)
{
	struct interface *ifp;
	const char *affname;
	struct if_link_params *iflp;
	struct affinity_map *affmap;
	enum affinity_mode affinity_mode;

	affname = yang_dnode_get_string(args->dnode, ".");
	affinity_mode = yang_dnode_get_enum(args->dnode, "../../affinity-mode");

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		iflp = if_link_params_get(ifp);
		affmap = affinity_map_get(affname);

		if (affmap->bit_position < 32 &&
		    (affinity_mode == AFFINITY_MODE_STANDARD ||
		     affinity_mode == AFFINITY_MODE_BOTH)) {
			iflp->admin_grp &= ~(1 << affmap->bit_position);
			if (iflp->admin_grp == 0)
				UNSET_PARAM(iflp, LP_ADM_GRP);
		}
		if (affinity_mode == AFFINITY_MODE_EXTENDED ||
		    affinity_mode == AFFINITY_MODE_BOTH) {
			admin_group_unset(&iflp->ext_admin_grp,
					  affmap->bit_position);
			if (admin_group_zero(&iflp->ext_admin_grp))
				UNSET_PARAM(iflp, LP_EXTEND_ADM_GRP);
		}

		if (if_is_operative(ifp))
			zebra_interface_parameters_update(ifp);
		break;
	}
	return NB_OK;
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-zebra:zebra/link-params/affinity-mode
 */
int lib_interface_zebra_affinity_mode_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct if_link_params *iflp;
	enum affinity_mode affinity_mode;

	affinity_mode = yang_dnode_get_enum(args->dnode, ".");

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		iflp = if_link_params_get(ifp);

		if (affinity_mode == AFFINITY_MODE_STANDARD) {
			if (!IS_PARAM_SET(iflp, LP_ADM_GRP) &&
			    IS_PARAM_SET(iflp, LP_EXTEND_ADM_GRP)) {
				iflp->admin_grp = admin_group_get_offset(
					&iflp->ext_admin_grp, 0);
				SET_PARAM(iflp, LP_ADM_GRP);
			}
			admin_group_clear(&iflp->ext_admin_grp);
			UNSET_PARAM(iflp, LP_EXTEND_ADM_GRP);
		}
		if (affinity_mode == AFFINITY_MODE_EXTENDED) {
			if (!IS_PARAM_SET(iflp, LP_EXTEND_ADM_GRP) &&
			    IS_PARAM_SET(iflp, LP_ADM_GRP)) {
				admin_group_bulk_set(&iflp->ext_admin_grp,
						     iflp->admin_grp, 0);
				SET_PARAM(iflp, LP_EXTEND_ADM_GRP);
			}
			iflp->admin_grp = 0;
			UNSET_PARAM(iflp, LP_ADM_GRP);
		}
		if (affinity_mode == AFFINITY_MODE_BOTH) {
			if (!IS_PARAM_SET(iflp, LP_EXTEND_ADM_GRP) &&
			    IS_PARAM_SET(iflp, LP_ADM_GRP)) {
				admin_group_bulk_set(&iflp->ext_admin_grp,
						     iflp->admin_grp, 0);
				SET_PARAM(iflp, LP_EXTEND_ADM_GRP);
			} else if (!IS_PARAM_SET(iflp, LP_ADM_GRP) &&
				   IS_PARAM_SET(iflp, LP_EXTEND_ADM_GRP)) {
				iflp->admin_grp = admin_group_get_offset(
					&iflp->ext_admin_grp, 0);
				SET_PARAM(iflp, LP_ADM_GRP);
			}
		}

		if (if_is_operative(ifp))
			zebra_interface_parameters_update(ifp);
		break;
	}
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
	struct zebra_l3vni *zl3vni = NULL;
	char err[ERR_STR_SZ];
	bool pfx_only = false;
	const struct lyd_node *pn_dnode;
	const char *vrfname;

	switch (args->event) {
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_VALIDATE:
		vni = yang_dnode_get_uint32(args->dnode, NULL);
		/* Get vrf info from parent node, reject configuration
		 * if zebra vrf already mapped to different vni id.
		 */
		pn_dnode = yang_dnode_get_parent(args->dnode, "vrf");
		vrfname = yang_dnode_get_string(pn_dnode, "name");
		zvrf = zebra_vrf_lookup_by_name(vrfname);
		if (!zvrf) {
			snprintf(args->errmsg, args->errmsg_len,
				 "zebra vrf info not found for vrf:%s.",
				 vrfname);
			return NB_ERR_VALIDATION;
		}
		if (zvrf->l3vni && zvrf->l3vni != vni) {
			snprintf(
				args->errmsg, args->errmsg_len,
				"vni %u cannot be configured as vni %u is already configured under the vrf",
				vni, zvrf->l3vni);
			return NB_ERR_VALIDATION;
		}

		/* Check if this VNI is already present in the system */
		zl3vni = zl3vni_lookup(vni);
		if (zl3vni) {
			snprintf(args->errmsg, args->errmsg_len,
				 "VNI %u is already configured as L3-VNI", vni);
			return NB_ERR_VALIDATION;
		}

		break;
	case NB_EV_APPLY:

		vrf = nb_running_get_entry(args->dnode, NULL, true);
		zvrf = zebra_vrf_lookup_by_name(vrf->name);
		vni = yang_dnode_get_uint32(args->dnode, NULL);
		/* Note: This covers lib_vrf_zebra_prefix_only_modify() config
		 * along with l3vni config
		 */
		pfx_only = yang_dnode_get_bool(args->dnode, "../prefix-only");

		if (zebra_vxlan_process_vrf_vni_cmd(zvrf, vni, err, ERR_STR_SZ,
						    pfx_only ? 1 : 0, 1)
		    != 0) {
			if (IS_ZEBRA_DEBUG_VXLAN)
				snprintf(
					args->errmsg, args->errmsg_len,
					"vrf vni %u mapping failed with error: %s",
					vni, err);
			return NB_ERR;
		}

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
		return NB_OK;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		zvrf = zebra_vrf_lookup_by_name(vrf->name);
		vni = yang_dnode_get_uint32(args->dnode, NULL);

		if (!zl3vni_lookup(vni))
			return NB_OK;

		if (zvrf->l3vni != vni) {
			snprintf(args->errmsg, args->errmsg_len,
				 "vrf %s has different vni %u mapped",
				 vrf->name, zvrf->l3vni);
			return NB_ERR;
		}

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
