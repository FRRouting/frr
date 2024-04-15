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
#include "zebra/zebra_evpn_mh.h"
#include "zebra/zebra_ptm.h"
#include "zebra/router-id.h"
#include "zebra/zebra_routemap.h"
#include "zebra/zebra_rnh.h"
#include "zebra/table_manager.h"

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

#if HAVE_BFDD == 0
/*
 * XPath: /frr-zebra:zebra/ptm-enable
 */
int zebra_ptm_enable_modify(struct nb_cb_modify_args *args)
{
	bool ptm;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ptm = yang_dnode_get_bool(args->dnode, NULL);

	if (ptm)
		zebra_global_ptm_enable();
	else
		zebra_global_ptm_disable();

	return NB_OK;
}
#endif

/*
 * XPath: /frr-zebra:zebra/route-map-delay
 */
int zebra_route_map_delay_modify(struct nb_cb_modify_args *args)
{
	uint32_t delay = yang_dnode_get_uint32(args->dnode, NULL);

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	zebra_route_map_set_delay_timer(delay);

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

	/*
	 * The interface is updated in the apply_finish callback after all
	 * parameters are set in the corresponding callbacks.
	 */

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

void lib_interface_zebra_link_params_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	struct interface *ifp;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	if (if_is_operative(ifp))
		zebra_interface_parameters_update(ifp);
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/link-params/metric
 */
int lib_interface_zebra_link_params_metric_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct if_link_params *iflp;
	uint32_t metric;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	iflp = if_link_params_get(ifp);
	metric = yang_dnode_get_uint32(args->dnode, NULL);

	link_param_cmd_set_uint32(ifp, &iflp->te_metric, LP_TE_METRIC, metric);

	return NB_OK;
}

int lib_interface_zebra_link_params_metric_destroy(struct nb_cb_destroy_args *args)
{
	struct interface *ifp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);

	link_param_cmd_unset(ifp, LP_TE_METRIC);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/link-params/max-bandwidth
 */
int lib_interface_zebra_link_params_max_bandwidth_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct if_link_params *iflp;
	float max_bw, res_bw, ava_bw, use_bw;

	max_bw = yang_dnode_get_bandwidth_ieee_float32(args->dnode, NULL);

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (yang_dnode_exists(args->dnode, "../residual-bandwidth")) {
			res_bw = yang_dnode_get_bandwidth_ieee_float32(
				args->dnode, "../residual-bandwidth");
			if (max_bw < res_bw) {
				snprintfrr(args->errmsg, args->errmsg_len,
					   "max-bandwidth %f is less than residual-bandwidth %f",
					   max_bw, res_bw);
				return NB_ERR_VALIDATION;
			}
		}
		if (yang_dnode_exists(args->dnode, "../available-bandwidth")) {
			ava_bw = yang_dnode_get_bandwidth_ieee_float32(
				args->dnode, "../available-bandwidth");
			if (max_bw < ava_bw) {
				snprintfrr(args->errmsg, args->errmsg_len,
					   "max-bandwidth %f is less than available-bandwidth %f",
					   max_bw, ava_bw);
				return NB_ERR_VALIDATION;
			}
		}
		if (yang_dnode_exists(args->dnode, "../utilized-bandwidth")) {
			use_bw = yang_dnode_get_bandwidth_ieee_float32(
				args->dnode, "../utilized-bandwidth");
			if (max_bw < use_bw) {
				snprintfrr(args->errmsg, args->errmsg_len,
					   "max-bandwidth %f is less than utilized-bandwidth %f",
					   max_bw, use_bw);
				return NB_ERR_VALIDATION;
			}
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		iflp = if_link_params_get(ifp);
		link_param_cmd_set_float(ifp, &iflp->max_bw, LP_MAX_BW, max_bw);
		break;
	}

	return NB_OK;
}

int lib_interface_zebra_link_params_max_bandwidth_destroy(
	struct nb_cb_destroy_args *args)
{
	if (args->event == NB_EV_VALIDATE) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   "Removing max-bandwidth is not allowed");
		return NB_ERR_VALIDATION;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/link-params/max-reservable-bandwidth
 */
int lib_interface_zebra_link_params_max_reservable_bandwidth_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct if_link_params *iflp;
	float max_rsv_bw;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	max_rsv_bw = yang_dnode_get_bandwidth_ieee_float32(args->dnode, NULL);

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	iflp = if_link_params_get(ifp);
	link_param_cmd_set_float(ifp, &iflp->max_rsv_bw, LP_MAX_RSV_BW,
				 max_rsv_bw);

	return NB_OK;
}

int lib_interface_zebra_link_params_max_reservable_bandwidth_destroy(
	struct nb_cb_destroy_args *args)
{
	if (args->event == NB_EV_VALIDATE) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   "Removing max-reservable-bandwidth is not allowed");
		return NB_ERR_VALIDATION;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/link-params/unreserved-bandwidths/unreserved-bandwidth
 */
int lib_interface_zebra_link_params_unreserved_bandwidths_unreserved_bandwidth_create(
	struct nb_cb_create_args *args)
{
	struct interface *ifp;
	struct if_link_params *iflp;
	uint8_t priority;
	float unrsv_bw;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	priority = yang_dnode_get_uint8(args->dnode, "priority");
	unrsv_bw = yang_dnode_get_bandwidth_ieee_float32(args->dnode,
							 "unreserved-bandwidth");

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	iflp = if_link_params_get(ifp);
	link_param_cmd_set_float(ifp, &iflp->unrsv_bw[priority], LP_UNRSV_BW,
				 unrsv_bw);

	return NB_OK;
}

int lib_interface_zebra_link_params_unreserved_bandwidths_unreserved_bandwidth_destroy(
	struct nb_cb_destroy_args *args)
{
	if (args->event == NB_EV_VALIDATE) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   "Removing unreserved-bandwidth is not allowed");
		return NB_ERR_VALIDATION;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/link-params/unreserved-bandwidths/unreserved-bandwidth/unreserved-bandwidth
 */
int lib_interface_zebra_link_params_unreserved_bandwidths_unreserved_bandwidth_unreserved_bandwidth_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct if_link_params *iflp;
	uint8_t priority;
	float unrsv_bw;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	priority = yang_dnode_get_uint8(args->dnode, "../priority");
	unrsv_bw = yang_dnode_get_bandwidth_ieee_float32(args->dnode, NULL);

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	iflp = if_link_params_get(ifp);
	link_param_cmd_set_float(ifp, &iflp->unrsv_bw[priority], LP_UNRSV_BW,
				 unrsv_bw);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/link-params/residual-bandwidth
 */
int lib_interface_zebra_link_params_residual_bandwidth_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct if_link_params *iflp;
	float max_bw, res_bw;

	res_bw = yang_dnode_get_bandwidth_ieee_float32(args->dnode, NULL);

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (yang_dnode_exists(args->dnode, "../max-bandwidth")) {
			max_bw =
				yang_dnode_get_bandwidth_ieee_float32(args->dnode,
								      "../max-bandwidth");
			if (max_bw < res_bw) {
				snprintfrr(args->errmsg, args->errmsg_len,
					   "max-bandwidth %f is less than residual-bandwidth %f",
					   max_bw, res_bw);
				return NB_ERR_VALIDATION;
			}
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		iflp = if_link_params_get(ifp);
		link_param_cmd_set_float(ifp, &iflp->res_bw, LP_RES_BW, res_bw);
		break;
	}

	return NB_OK;
}

int lib_interface_zebra_link_params_residual_bandwidth_destroy(
	struct nb_cb_destroy_args *args)
{
	struct interface *ifp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	link_param_cmd_unset(ifp, LP_RES_BW);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/link-params/available-bandwidth
 */
int lib_interface_zebra_link_params_available_bandwidth_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct if_link_params *iflp;
	float max_bw, ava_bw;

	ava_bw = yang_dnode_get_bandwidth_ieee_float32(args->dnode, NULL);

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (yang_dnode_exists(args->dnode, "../max-bandwidth")) {
			max_bw =
				yang_dnode_get_bandwidth_ieee_float32(args->dnode,
								      "../max-bandwidth");
			if (max_bw < ava_bw) {
				snprintfrr(args->errmsg, args->errmsg_len,
					   "max-bandwidth %f is less than available-bandwidth %f",
					   max_bw, ava_bw);
				return NB_ERR_VALIDATION;
			}
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		iflp = if_link_params_get(ifp);
		link_param_cmd_set_float(ifp, &iflp->ava_bw, LP_AVA_BW, ava_bw);
		break;
	}

	return NB_OK;
}

int lib_interface_zebra_link_params_available_bandwidth_destroy(
	struct nb_cb_destroy_args *args)
{
	struct interface *ifp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	link_param_cmd_unset(ifp, LP_AVA_BW);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/link-params/utilized-bandwidth
 */
int lib_interface_zebra_link_params_utilized_bandwidth_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct if_link_params *iflp;
	float max_bw, use_bw;

	use_bw = yang_dnode_get_bandwidth_ieee_float32(args->dnode, NULL);

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (yang_dnode_exists(args->dnode, "../max-bandwidth")) {
			max_bw =
				yang_dnode_get_bandwidth_ieee_float32(args->dnode,
								      "../max-bandwidth");
			if (max_bw < use_bw) {
				snprintfrr(args->errmsg, args->errmsg_len,
					   "max-bandwidth %f is less than utilized-bandwidth %f",
					   max_bw, use_bw);
				return NB_ERR_VALIDATION;
			}
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		iflp = if_link_params_get(ifp);
		link_param_cmd_set_float(ifp, &iflp->use_bw, LP_USE_BW, use_bw);
		break;
	}

	return NB_OK;
}

int lib_interface_zebra_link_params_utilized_bandwidth_destroy(
	struct nb_cb_destroy_args *args)
{
	struct interface *ifp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	link_param_cmd_unset(ifp, LP_USE_BW);

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
		break;
	}
	return NB_OK;
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-zebra:zebra/link-params/affinities
 */
int lib_interface_zebra_affinities_create(struct nb_cb_create_args *args)
{
	return NB_OK;
}

int lib_interface_zebra_affinities_destroy(struct nb_cb_destroy_args *args)
{
	struct interface *ifp;
	struct if_link_params *iflp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	iflp = if_link_params_get(ifp);

	iflp->admin_grp = 0;
	UNSET_PARAM(iflp, LP_ADM_GRP);

	admin_group_clear(&iflp->ext_admin_grp);
	UNSET_PARAM(iflp, LP_EXTEND_ADM_GRP);

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
		break;
	}
	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/link-params/neighbor
 */
int lib_interface_zebra_link_params_neighbor_create(struct nb_cb_create_args *args)
{
	struct interface *ifp;
	struct if_link_params *iflp;
	struct in_addr ip;
	uint32_t as;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	as = yang_dnode_get_uint32(args->dnode, "remote-as");
	yang_dnode_get_ipv4(&ip, args->dnode, "ipv4-remote-id");

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	iflp = if_link_params_get(ifp);

	iflp->rmt_as = as;
	iflp->rmt_ip = ip;
	SET_PARAM(iflp, LP_RMT_AS);

	return NB_OK;
}

int lib_interface_zebra_link_params_neighbor_destroy(
	struct nb_cb_destroy_args *args)
{
	struct interface *ifp;
	struct if_link_params *iflp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	iflp = if_link_params_get(ifp);

	iflp->rmt_as = 0;
	iflp->rmt_ip.s_addr = 0;
	UNSET_PARAM(iflp, LP_RMT_AS);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/link-params/neighbor/remote-as
 */
int lib_interface_zebra_link_params_neighbor_remote_as_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct if_link_params *iflp;
	uint32_t as;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	as = yang_dnode_get_uint32(args->dnode, NULL);

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	iflp = if_link_params_get(ifp);

	iflp->rmt_as = as;

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/link-params/neighbor/ipv4-remote-id
 */
int lib_interface_zebra_link_params_neighbor_ipv4_remote_id_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct if_link_params *iflp;
	struct in_addr ip;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	yang_dnode_get_ipv4(&ip, args->dnode, NULL);

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	iflp = if_link_params_get(ifp);

	iflp->rmt_ip = ip;

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/link-params/delay
 */
int lib_interface_zebra_link_params_delay_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct if_link_params *iflp;
	uint32_t delay;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	delay = yang_dnode_get_uint32(args->dnode, NULL);

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	iflp = if_link_params_get(ifp);

	link_param_cmd_set_uint32(ifp, &iflp->av_delay, LP_DELAY, delay);

	return NB_OK;
}

int lib_interface_zebra_link_params_delay_destroy(struct nb_cb_destroy_args *args)
{
	struct interface *ifp;
	struct if_link_params *iflp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	iflp = if_link_params_get(ifp);

	iflp->av_delay = 0;
	link_param_cmd_unset(ifp, LP_DELAY);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/link-params/min-max-delay
 */
int lib_interface_zebra_link_params_min_max_delay_create(
	struct nb_cb_create_args *args)
{
	struct interface *ifp;
	struct if_link_params *iflp;
	uint32_t delay_min, delay_max;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	delay_min = yang_dnode_get_uint32(args->dnode, "delay-min");
	delay_max = yang_dnode_get_uint32(args->dnode, "delay-max");

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	iflp = if_link_params_get(ifp);

	iflp->min_delay = delay_min;
	iflp->max_delay = delay_max;
	SET_PARAM(iflp, LP_MM_DELAY);

	return NB_OK;
}

int lib_interface_zebra_link_params_min_max_delay_destroy(
	struct nb_cb_destroy_args *args)
{
	struct interface *ifp;
	struct if_link_params *iflp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	iflp = if_link_params_get(ifp);

	iflp->min_delay = 0;
	iflp->max_delay = 0;
	UNSET_PARAM(iflp, LP_MM_DELAY);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/link-params/min-max-delay/delay-min
 */
int lib_interface_zebra_link_params_min_max_delay_delay_min_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct if_link_params *iflp;
	uint32_t delay_min;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	delay_min = yang_dnode_get_uint32(args->dnode, NULL);

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	iflp = if_link_params_get(ifp);

	iflp->min_delay = delay_min;

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/link-params/min-max-delay/delay-max
 */
int lib_interface_zebra_link_params_min_max_delay_delay_max_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct if_link_params *iflp;
	uint32_t delay_max;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	delay_max = yang_dnode_get_uint32(args->dnode, NULL);

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	iflp = if_link_params_get(ifp);

	iflp->max_delay = delay_max;

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/link-params/delay-variation
 */
int lib_interface_zebra_link_params_delay_variation_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct if_link_params *iflp;
	uint32_t delay_var;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	delay_var = yang_dnode_get_uint32(args->dnode, NULL);

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	iflp = if_link_params_get(ifp);

	link_param_cmd_set_uint32(ifp, &iflp->delay_var, LP_DELAY_VAR,
				  delay_var);

	return NB_OK;
}

int lib_interface_zebra_link_params_delay_variation_destroy(
	struct nb_cb_destroy_args *args)
{
	struct interface *ifp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);

	link_param_cmd_unset(ifp, LP_DELAY_VAR);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/link-params/packet-loss
 */
int lib_interface_zebra_link_params_packet_loss_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct if_link_params *iflp;
	double packet_loss;
	uint32_t value;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	packet_loss = yang_dnode_get_dec64(args->dnode, NULL);
	value = (uint32_t)(packet_loss / LOSS_PRECISION);

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	iflp = if_link_params_get(ifp);

	link_param_cmd_set_uint32(ifp, &iflp->pkt_loss, LP_PKT_LOSS, value);

	return NB_OK;
}

int lib_interface_zebra_link_params_packet_loss_destroy(
	struct nb_cb_destroy_args *args)
{
	struct interface *ifp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);

	link_param_cmd_unset(ifp, LP_PKT_LOSS);

	return NB_OK;
}

static bool evpn_mh_dnode_to_esi(const struct lyd_node *dnode, esi_t *esi)
{
	if (yang_dnode_exists(dnode, "type-0/esi")) {
		if (!str_to_esi(yang_dnode_get_string(dnode, "type-0/esi"), esi))
			assert(false);
	} else if (yang_dnode_exists(dnode, "type-3/system-mac") &&
		   yang_dnode_exists(dnode, "type-3/local-discriminator")) {
		struct ethaddr mac;
		uint32_t lid;

		yang_dnode_get_mac(&mac, dnode, "type-3/system-mac");
		lid = yang_dnode_get_uint32(dnode, "type-3/local-discriminator");

		zebra_build_type3_esi(lid, &mac, esi);
	} else {
		return false;
	}

	return true;
}

struct esi_cmp_iter_arg {
	struct lyd_node *dnode;
	esi_t esi;
	bool exists;
};

static int esi_cmp_iter_cb(const struct lyd_node *dnode, void *arg)
{
	struct esi_cmp_iter_arg *iter = arg;
	esi_t esi;

	if (dnode == iter->dnode)
		return YANG_ITER_CONTINUE;

	if (!evpn_mh_dnode_to_esi(dnode, &esi))
		return YANG_ITER_CONTINUE;

	if (!memcmp(&esi, &iter->esi, ESI_BYTES)) {
		iter->exists = true;
		return YANG_ITER_STOP;
	}

	return YANG_ITER_CONTINUE;
}

/* evpn-mh should be passed to this function */
static bool esi_unique(struct lyd_node *dnode)
{
	struct esi_cmp_iter_arg iter;

	iter.dnode = dnode;
	evpn_mh_dnode_to_esi(dnode, &iter.esi);
	iter.exists = false;

	yang_dnode_iterate(esi_cmp_iter_cb, &iter, dnode,
			   "/frr-interface:lib/interface/frr-zebra:zebra/evpn-mh");

	if (iter.exists)
		return false;

	return true;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/evpn-mh/type-0
 */
int lib_interface_zebra_evpn_mh_type_0_create(struct nb_cb_create_args *args)
{
	return NB_OK;
}

int lib_interface_zebra_evpn_mh_type_0_destroy(struct nb_cb_destroy_args *args)
{
	struct interface *ifp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	zebra_evpn_es_type0_esi_update(ifp->info, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/evpn-mh/type-0/esi
 */
int lib_interface_zebra_evpn_mh_type_0_esi_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	esi_t esi;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (!esi_unique(lyd_parent(lyd_parent(args->dnode)))) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "ESI already exists on a different interface");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		if (!str_to_esi(yang_dnode_get_string(args->dnode, NULL), &esi))
			assert(false);
		zebra_evpn_es_type0_esi_update(ifp->info, &esi);
		break;
	}

	return NB_OK;
}

int lib_interface_zebra_evpn_mh_type_0_esi_destroy(struct nb_cb_destroy_args *args)
{
	struct interface *ifp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	zebra_evpn_es_type0_esi_update(ifp->info, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/evpn-mh/type-3
 */
int lib_interface_zebra_evpn_mh_type_3_create(struct nb_cb_create_args *args)
{
	return NB_OK;
}

int lib_interface_zebra_evpn_mh_type_3_destroy(struct nb_cb_destroy_args *args)
{
	struct interface *ifp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	zebra_evpn_es_sys_mac_update(ifp->info, NULL);
	zebra_evpn_es_lid_update(ifp->info, 0);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/evpn-mh/type-3/system-mac
 */
int lib_interface_zebra_evpn_mh_type_3_system_mac_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct ethaddr mac;

	yang_dnode_get_mac(&mac, args->dnode, NULL);

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (is_zero_mac(&mac)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "MAC cannot be all-zeroes");
			return NB_ERR_VALIDATION;
		}
		if (!esi_unique(lyd_parent(lyd_parent(args->dnode)))) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "ESI already exists on a different interface");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		zebra_evpn_es_sys_mac_update(ifp->info, &mac);
		break;
	}

	return NB_OK;
}

int lib_interface_zebra_evpn_mh_type_3_system_mac_destroy(
	struct nb_cb_destroy_args *args)
{
	struct interface *ifp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	zebra_evpn_es_sys_mac_update(ifp->info, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/evpn-mh/type-3/local-discriminator
 */
int lib_interface_zebra_evpn_mh_type_3_local_discriminator_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	uint32_t lid;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (!esi_unique(lyd_parent(lyd_parent(args->dnode)))) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "ESI already exists on a different interface");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		lid = yang_dnode_get_uint32(args->dnode, NULL);
		zebra_evpn_es_lid_update(ifp->info, lid);
		break;
	}

	return NB_OK;
}

int lib_interface_zebra_evpn_mh_type_3_local_discriminator_destroy(
	struct nb_cb_destroy_args *args)
{
	struct interface *ifp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	zebra_evpn_es_lid_update(ifp->info, 0);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/evpn-mh/df-preference
 */
int lib_interface_zebra_evpn_mh_df_preference_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	uint16_t df_pref;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	df_pref = yang_dnode_get_uint16(args->dnode, NULL);
	zebra_evpn_es_df_pref_update(ifp->info, df_pref);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/evpn-mh/bypass
 */
int lib_interface_zebra_evpn_mh_bypass_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	bool bypass;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	bypass = yang_dnode_get_bool(args->dnode, NULL);
	zebra_evpn_es_bypass_cfg_update(ifp->info, bypass);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/evpn-mh/uplink
 */
int lib_interface_zebra_evpn_mh_uplink_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	bool uplink;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	uplink = yang_dnode_get_bool(args->dnode, NULL);
	zebra_evpn_mh_uplink_cfg_update(ifp->info, uplink);

	return NB_OK;
}

#if defined(HAVE_RTADV)
/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/send-advertisements
 */
int lib_interface_zebra_ipv6_router_advertisements_send_advertisements_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct zebra_if *zif;
	bool send_adv;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	zif = ifp->info;

	send_adv = yang_dnode_get_bool(args->dnode, NULL);

	if (send_adv) {
		ipv6_nd_suppress_ra_set(ifp, RA_ENABLE);
		SET_FLAG(zif->rtadv.ra_configured, VTY_RA_CONFIGURED);
	} else {
		if (!CHECK_FLAG(zif->rtadv.ra_configured, BGP_RA_CONFIGURED))
			ipv6_nd_suppress_ra_set(ifp, RA_SUPPRESS);
		UNSET_FLAG(zif->rtadv.ra_configured, VTY_RA_CONFIGURED);
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/max-rtr-adv-interval
 */
int lib_interface_zebra_ipv6_router_advertisements_max_rtr_adv_interval_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	uint32_t interval;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	interval = yang_dnode_get_uint32(args->dnode, NULL);

	ipv6_nd_interval_set(ifp, interval);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/managed-flag
 */
int lib_interface_zebra_ipv6_router_advertisements_managed_flag_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct zebra_if *zif;
	bool managed_flag;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	zif = ifp->info;

	managed_flag = yang_dnode_get_bool(args->dnode, NULL);

	zif->rtadv.AdvManagedFlag = managed_flag;

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/other-config-flag
 */
int lib_interface_zebra_ipv6_router_advertisements_other_config_flag_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct zebra_if *zif;
	bool other_config_flag;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	zif = ifp->info;

	other_config_flag = yang_dnode_get_bool(args->dnode, NULL);

	zif->rtadv.AdvOtherConfigFlag = other_config_flag;

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/home-agent-flag
 */
int lib_interface_zebra_ipv6_router_advertisements_home_agent_flag_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct zebra_if *zif;
	bool home_agent_flag;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	zif = ifp->info;

	home_agent_flag = yang_dnode_get_bool(args->dnode, NULL);

	zif->rtadv.AdvHomeAgentFlag = home_agent_flag;

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/link-mtu
 */
int lib_interface_zebra_ipv6_router_advertisements_link_mtu_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct zebra_if *zif;
	uint32_t mtu;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	zif = ifp->info;

	mtu = yang_dnode_get_uint32(args->dnode, NULL);

	zif->rtadv.AdvLinkMTU = mtu;

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/reachable-time
 */
int lib_interface_zebra_ipv6_router_advertisements_reachable_time_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct zebra_if *zif;
	uint32_t time;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	zif = ifp->info;
	time = yang_dnode_get_uint32(args->dnode, NULL);

	zif->rtadv.AdvReachableTime = time;

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/retrans-timer
 */
int lib_interface_zebra_ipv6_router_advertisements_retrans_timer_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct zebra_if *zif;
	uint32_t timer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	zif = ifp->info;
	timer = yang_dnode_get_uint32(args->dnode, NULL);

	zif->rtadv.AdvRetransTimer = timer;

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/cur-hop-limit
 */
int lib_interface_zebra_ipv6_router_advertisements_cur_hop_limit_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct zebra_if *zif;
	uint8_t limit;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	zif = ifp->info;
	limit = yang_dnode_get_uint8(args->dnode, NULL);

	zif->rtadv.AdvCurHopLimit = limit;

	return NB_OK;
}

int lib_interface_zebra_ipv6_router_advertisements_cur_hop_limit_destroy(
	struct nb_cb_destroy_args *args)
{
	struct interface *ifp;
	struct zebra_if *zif;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	zif = ifp->info;

	zif->rtadv.AdvCurHopLimit = RTADV_DEFAULT_HOPLIMIT;

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/default-lifetime
 */
int lib_interface_zebra_ipv6_router_advertisements_default_lifetime_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct zebra_if *zif;
	uint16_t lifetime;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	zif = ifp->info;

	lifetime = yang_dnode_get_uint16(args->dnode, NULL);

	zif->rtadv.AdvDefaultLifetime = lifetime;

	return NB_OK;
}

int lib_interface_zebra_ipv6_router_advertisements_default_lifetime_destroy(
	struct nb_cb_destroy_args *args)
{
	struct interface *ifp;
	struct zebra_if *zif;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	zif = ifp->info;

	zif->rtadv.AdvDefaultLifetime = -1;

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/fast-retransmit
 */
int lib_interface_zebra_ipv6_router_advertisements_fast_retransmit_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct zebra_if *zif;
	bool fast_retransmit;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	zif = ifp->info;

	fast_retransmit = yang_dnode_get_bool(args->dnode, NULL);

	zif->rtadv.UseFastRexmit = fast_retransmit;

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/advertisement-interval-option
 */
int lib_interface_zebra_ipv6_router_advertisements_advertisement_interval_option_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct zebra_if *zif;
	bool option;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	zif = ifp->info;

	option = yang_dnode_get_bool(args->dnode, NULL);

	zif->rtadv.AdvIntervalOption = option;

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/home-agent-preference
 */
int lib_interface_zebra_ipv6_router_advertisements_home_agent_preference_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct zebra_if *zif;
	uint16_t preference;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	zif = ifp->info;

	preference = yang_dnode_get_uint16(args->dnode, NULL);

	zif->rtadv.HomeAgentPreference = preference;

	return NB_OK;
}

int lib_interface_zebra_ipv6_router_advertisements_home_agent_preference_destroy(
	struct nb_cb_destroy_args *args)
{
	struct interface *ifp;
	struct zebra_if *zif;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	zif = ifp->info;

	zif->rtadv.HomeAgentPreference = 0;

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/home-agent-lifetime
 */
int lib_interface_zebra_ipv6_router_advertisements_home_agent_lifetime_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct zebra_if *zif;
	uint16_t lifetime;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	zif = ifp->info;

	lifetime = yang_dnode_get_uint16(args->dnode, NULL);

	zif->rtadv.HomeAgentLifetime = lifetime;

	return NB_OK;
}

int lib_interface_zebra_ipv6_router_advertisements_home_agent_lifetime_destroy(
	struct nb_cb_destroy_args *args)
{
	struct interface *ifp;
	struct zebra_if *zif;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	zif = ifp->info;

	zif->rtadv.HomeAgentLifetime = -1;

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/default-router-preference
 */
int lib_interface_zebra_ipv6_router_advertisements_default_router_preference_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct zebra_if *zif;
	int preference;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	zif = ifp->info;

	preference = yang_dnode_get_enum(args->dnode, NULL);

	zif->rtadv.DefaultPreference = preference;

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/prefix-list/prefix
 */
int lib_interface_zebra_ipv6_router_advertisements_prefix_list_prefix_create(
	struct nb_cb_create_args *args)
{
	struct interface *ifp;
	struct rtadv_prefix rp, *prefix;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);

	yang_dnode_get_ipv6p(&rp.prefix, args->dnode, "prefix-spec");
	rp.AdvOnLinkFlag = yang_dnode_get_bool(args->dnode, "on-link-flag");
	rp.AdvAutonomousFlag = yang_dnode_get_bool(args->dnode,
						   "autonomous-flag");
	rp.AdvRouterAddressFlag = yang_dnode_get_bool(args->dnode,
						      "router-address-flag");
	rp.AdvValidLifetime = yang_dnode_get_uint32(args->dnode,
						    "valid-lifetime");
	rp.AdvPreferredLifetime = yang_dnode_get_uint32(args->dnode,
							"preferred-lifetime");

	prefix = rtadv_add_prefix_manual(ifp->info, &rp);
	nb_running_set_entry(args->dnode, prefix);

	return NB_OK;
}

int lib_interface_zebra_ipv6_router_advertisements_prefix_list_prefix_destroy(
	struct nb_cb_destroy_args *args)
{
	struct interface *ifp;
	struct rtadv_prefix *prefix;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	prefix = nb_running_unset_entry(args->dnode);
	ifp = nb_running_get_entry(args->dnode, NULL, true);

	rtadv_delete_prefix_manual(ifp->info, prefix);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/prefix-list/prefix/valid-lifetime
 */
int lib_interface_zebra_ipv6_router_advertisements_prefix_list_prefix_valid_lifetime_modify(
	struct nb_cb_modify_args *args)
{
	struct rtadv_prefix *prefix;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	prefix = nb_running_get_entry(args->dnode, NULL, true);

	prefix->AdvValidLifetime = yang_dnode_get_uint32(args->dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/prefix-list/prefix/on-link-flag
 */
int lib_interface_zebra_ipv6_router_advertisements_prefix_list_prefix_on_link_flag_modify(
	struct nb_cb_modify_args *args)
{
	struct rtadv_prefix *prefix;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	prefix = nb_running_get_entry(args->dnode, NULL, true);

	prefix->AdvOnLinkFlag = yang_dnode_get_bool(args->dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/prefix-list/prefix/preferred-lifetime
 */
int lib_interface_zebra_ipv6_router_advertisements_prefix_list_prefix_preferred_lifetime_modify(
	struct nb_cb_modify_args *args)
{
	struct rtadv_prefix *prefix;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	prefix = nb_running_get_entry(args->dnode, NULL, true);

	prefix->AdvPreferredLifetime = yang_dnode_get_uint32(args->dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/prefix-list/prefix/autonomous-flag
 */
int lib_interface_zebra_ipv6_router_advertisements_prefix_list_prefix_autonomous_flag_modify(
	struct nb_cb_modify_args *args)
{
	struct rtadv_prefix *prefix;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	prefix = nb_running_get_entry(args->dnode, NULL, true);

	prefix->AdvAutonomousFlag = yang_dnode_get_bool(args->dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/prefix-list/prefix/router-address-flag
 */
int lib_interface_zebra_ipv6_router_advertisements_prefix_list_prefix_router_address_flag_modify(
	struct nb_cb_modify_args *args)
{
	struct rtadv_prefix *prefix;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	prefix = nb_running_get_entry(args->dnode, NULL, true);

	prefix->AdvRouterAddressFlag = yang_dnode_get_bool(args->dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/rdnss/rdnss-address
 */
int lib_interface_zebra_ipv6_router_advertisements_rdnss_rdnss_address_create(
	struct nb_cb_create_args *args)
{
	struct interface *ifp;
	struct rtadv_rdnss rdnss = {{{{0}}}}, *p;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);

	yang_dnode_get_ipv6(&rdnss.addr, args->dnode, "address");
	if (yang_dnode_exists(args->dnode, "lifetime")) {
		rdnss.lifetime = yang_dnode_get_uint32(args->dnode, "lifetime");
		rdnss.lifetime_set = 1;
	} else {
		rdnss.lifetime_set = 0;
	}

	p = rtadv_rdnss_set(ifp->info, &rdnss);
	nb_running_set_entry(args->dnode, p);

	return NB_OK;
}

int lib_interface_zebra_ipv6_router_advertisements_rdnss_rdnss_address_destroy(
	struct nb_cb_destroy_args *args)
{
	struct interface *ifp;
	struct rtadv_rdnss *p;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	p = nb_running_unset_entry(args->dnode);
	ifp = nb_running_get_entry(args->dnode, NULL, true);

	rtadv_rdnss_reset(ifp->info, p);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/rdnss/rdnss-address/lifetime
 */
int lib_interface_zebra_ipv6_router_advertisements_rdnss_rdnss_address_lifetime_modify(
	struct nb_cb_modify_args *args)
{
	struct rtadv_rdnss *p;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	p = nb_running_get_entry(args->dnode, NULL, true);

	p->lifetime = yang_dnode_get_uint32(args->dnode, NULL);
	p->lifetime_set = 1;

	return NB_OK;
}

int lib_interface_zebra_ipv6_router_advertisements_rdnss_rdnss_address_lifetime_destroy(
	struct nb_cb_destroy_args *args)
{
	struct rtadv_rdnss *p;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	p = nb_running_get_entry(args->dnode, NULL, true);

	p->lifetime_set = 0;

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/dnssl/dnssl-domain
 */
int lib_interface_zebra_ipv6_router_advertisements_dnssl_dnssl_domain_create(
	struct nb_cb_create_args *args)
{
	struct interface *ifp;
	struct rtadv_dnssl dnssl = {{0}}, *p;
	int ret;

	strlcpy(dnssl.name, yang_dnode_get_string(args->dnode, "domain"),
		sizeof(dnssl.name));
	ret = rtadv_dnssl_encode(dnssl.encoded_name, dnssl.name);
	dnssl.encoded_len = ret;

	if (args->event == NB_EV_VALIDATE) {
		if (ret < 0) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "Malformed DNS search domain");
			return NB_ERR_VALIDATION;
		}
	}

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);

	if (yang_dnode_exists(args->dnode, "lifetime")) {
		dnssl.lifetime = yang_dnode_get_uint32(args->dnode, "lifetime");
		dnssl.lifetime_set = 1;
	} else {
		dnssl.lifetime_set = 0;
	}

	p = rtadv_dnssl_set(ifp->info, &dnssl);
	nb_running_set_entry(args->dnode, p);

	return NB_OK;
}

int lib_interface_zebra_ipv6_router_advertisements_dnssl_dnssl_domain_destroy(
	struct nb_cb_destroy_args *args)
{
	struct interface *ifp;
	struct rtadv_dnssl *p;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	p = nb_running_unset_entry(args->dnode);
	ifp = nb_running_get_entry(args->dnode, NULL, true);

	rtadv_dnssl_reset(ifp->info, p);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/dnssl/dnssl-domain/lifetime
 */
int lib_interface_zebra_ipv6_router_advertisements_dnssl_dnssl_domain_lifetime_modify(
	struct nb_cb_modify_args *args)
{
	struct rtadv_dnssl *p;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	p = nb_running_get_entry(args->dnode, NULL, true);

	p->lifetime = yang_dnode_get_uint32(args->dnode, NULL);
	p->lifetime_set = 1;

	return NB_OK;
}

int lib_interface_zebra_ipv6_router_advertisements_dnssl_dnssl_domain_lifetime_destroy(
	struct nb_cb_destroy_args *args)
{
	struct rtadv_dnssl *p;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	p = nb_running_get_entry(args->dnode, NULL, true);

	p->lifetime_set = 0;

	return NB_OK;
}
#endif /* defined(HAVE_RTADV) */

#if HAVE_BFDD == 0
/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/ptm-enable
 */
int lib_interface_zebra_ptm_enable_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	bool ptm;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);

	ptm = yang_dnode_get_bool(args->dnode, NULL);
	if (ptm)
		zebra_if_ptm_enable(ifp);
	else
		zebra_if_ptm_disable(ifp);

	return NB_OK;
}
#endif

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:zebra/router-id
 */
int lib_vrf_zebra_router_id_modify(struct nb_cb_modify_args *args)
{
	struct vrf *vrf;
	struct prefix p;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	vrf = nb_running_get_entry(args->dnode, NULL, true);

	yang_dnode_get_ipv4p(&p, args->dnode, NULL);

	router_id_set(AFI_IP, &p, vrf->info);

	return NB_OK;
}

int lib_vrf_zebra_router_id_destroy(struct nb_cb_destroy_args *args)
{
	struct vrf *vrf;
	struct prefix p;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	vrf = nb_running_get_entry(args->dnode, NULL, true);

	memset(&p, 0, sizeof(p));
	p.family = AF_INET;

	router_id_set(AFI_IP, &p, vrf->info);

	return NB_OK;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:zebra/ipv6-router-id
 */
int lib_vrf_zebra_ipv6_router_id_modify(struct nb_cb_modify_args *args)
{
	struct vrf *vrf;
	struct prefix p;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	vrf = nb_running_get_entry(args->dnode, NULL, true);

	yang_dnode_get_ipv6p(&p, args->dnode, NULL);

	router_id_set(AFI_IP6, &p, vrf->info);

	return NB_OK;
}

int lib_vrf_zebra_ipv6_router_id_destroy(struct nb_cb_destroy_args *args)
{
	struct vrf *vrf;
	struct prefix p;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	vrf = nb_running_get_entry(args->dnode, NULL, true);

	memset(&p, 0, sizeof(p));
	p.family = AF_INET6;

	router_id_set(AFI_IP6, &p, vrf->info);

	return NB_OK;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:zebra/filter-protocol
 */
int lib_vrf_zebra_filter_protocol_create(struct nb_cb_create_args *args)
{
	const char *proto = yang_dnode_get_string(args->dnode, "protocol");
	int rtype;

	if (strcasecmp(proto, "any") == 0)
		rtype = ZEBRA_ROUTE_MAX;
	else
		rtype = proto_name2num(proto);

	if (args->event == NB_EV_VALIDATE)
		if (rtype < 0) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "invalid protocol name \"%s\"", proto);
			return NB_ERR_VALIDATION;
		}

	/* the creation finishes in the apply_finish callback */

	return NB_OK;
}

int lib_vrf_zebra_filter_protocol_destroy(struct nb_cb_destroy_args *args)
{
	struct vrf *vrf;
	const char *afi_safi = yang_dnode_get_string(args->dnode, "afi-safi");
	const char *proto = yang_dnode_get_string(args->dnode, "protocol");
	const char *rmap = yang_dnode_get_string(args->dnode, "route-map");
	afi_t afi;
	safi_t safi;
	int rtype;

	yang_afi_safi_identity2value(afi_safi, &afi, &safi);

	if (strcasecmp(proto, "any") == 0)
		rtype = ZEBRA_ROUTE_MAX;
	else
		rtype = proto_name2num(proto);

	/* deleting an existing entry, it can't be invalid */
	assert(rtype >= 0);

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	vrf = nb_running_get_entry(args->dnode, NULL, true);

	ip_protocol_rm_del(vrf->info, rmap, rtype, afi, safi);

	return NB_OK;
}

void lib_vrf_zebra_filter_protocol_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	struct vrf *vrf;
	const char *afi_safi = yang_dnode_get_string(args->dnode, "afi-safi");
	const char *proto = yang_dnode_get_string(args->dnode, "protocol");
	const char *rmap = yang_dnode_get_string(args->dnode, "route-map");
	afi_t afi;
	safi_t safi;
	int rtype;

	yang_afi_safi_identity2value(afi_safi, &afi, &safi);

	if (strcasecmp(proto, "any") == 0)
		rtype = ZEBRA_ROUTE_MAX;
	else
		rtype = proto_name2num(proto);

	/* finishing apply for a validated entry, it can't be invalid */
	assert(rtype >= 0);

	vrf = nb_running_get_entry(args->dnode, NULL, true);

	ip_protocol_rm_add(vrf->info, rmap, rtype, afi, safi);
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:zebra/filter-protocol/route-map
 */
int lib_vrf_zebra_filter_protocol_route_map_modify(struct nb_cb_modify_args *args)
{
	/* the update is done in the apply_finish callback */
	return NB_OK;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:zebra/filter-nht
 */
int lib_vrf_zebra_filter_nht_create(struct nb_cb_create_args *args)
{
	const char *afi_safi = yang_dnode_get_string(args->dnode, "afi-safi");
	const char *proto = yang_dnode_get_string(args->dnode, "protocol");
	afi_t afi;
	safi_t safi;
	int rtype;

	yang_afi_safi_identity2value(afi_safi, &afi, &safi);

	if (strcasecmp(proto, "any") == 0)
		rtype = ZEBRA_ROUTE_MAX;
	else
		rtype = proto_name2num(proto);

	if (args->event == NB_EV_VALIDATE) {
		if (rtype < 0) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "invalid protocol name \"%s\"", proto);
			return NB_ERR_VALIDATION;
		}
		if (safi != SAFI_UNICAST) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "only SAFI unicast is supported");
			return NB_ERR_VALIDATION;
		}
	}

	/* the creation finishes in the apply_finish callback */

	return NB_OK;
}

int lib_vrf_zebra_filter_nht_destroy(struct nb_cb_destroy_args *args)
{
	struct vrf *vrf;
	const char *afi_safi = yang_dnode_get_string(args->dnode, "afi-safi");
	const char *proto = yang_dnode_get_string(args->dnode, "protocol");
	const char *rmap = yang_dnode_get_string(args->dnode, "route-map");
	afi_t afi;
	safi_t safi;
	int rtype;

	yang_afi_safi_identity2value(afi_safi, &afi, &safi);

	if (strcasecmp(proto, "any") == 0)
		rtype = ZEBRA_ROUTE_MAX;
	else
		rtype = proto_name2num(proto);

	/* deleting an existing entry, it can't be invalid */
	assert(rtype >= 0);
	assert(safi == SAFI_UNICAST);

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	vrf = nb_running_get_entry(args->dnode, NULL, true);

	ip_nht_rm_del(vrf->info, rmap, rtype, afi);

	return NB_OK;
}

void lib_vrf_zebra_filter_nht_apply_finish(struct nb_cb_apply_finish_args *args)
{
	struct vrf *vrf;
	const char *afi_safi = yang_dnode_get_string(args->dnode, "afi-safi");
	const char *proto = yang_dnode_get_string(args->dnode, "protocol");
	const char *rmap = yang_dnode_get_string(args->dnode, "route-map");
	afi_t afi;
	safi_t safi;
	int rtype;

	yang_afi_safi_identity2value(afi_safi, &afi, &safi);

	if (strcasecmp(proto, "any") == 0)
		rtype = ZEBRA_ROUTE_MAX;
	else
		rtype = proto_name2num(proto);

	/* finishing apply for an existing entry, it can't be invalid */
	assert(rtype >= 0);
	assert(safi == SAFI_UNICAST);

	vrf = nb_running_get_entry(args->dnode, NULL, true);

	ip_nht_rm_add(vrf->info, rmap, rtype, afi);
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:zebra/filter-nht/route-map
 */
int lib_vrf_zebra_filter_nht_route_map_modify(struct nb_cb_modify_args *args)
{
	/* the update is done in the apply_finish callback */
	return NB_OK;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:zebra/resolve-via-default
 */
int lib_vrf_zebra_resolve_via_default_modify(struct nb_cb_modify_args *args)
{
	struct vrf *vrf;
	struct zebra_vrf *zvrf;
	bool resolve_via_default;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	vrf = nb_running_get_entry(args->dnode, NULL, true);
	zvrf = vrf->info;

	resolve_via_default = yang_dnode_get_bool(args->dnode, NULL);

	if (zvrf->zebra_rnh_ip_default_route == resolve_via_default)
		return NB_OK;

	zvrf->zebra_rnh_ip_default_route = resolve_via_default;

	zebra_evaluate_rnh(zvrf, AFI_IP, 0, NULL, SAFI_UNICAST);

	return NB_OK;
}

int lib_vrf_zebra_resolve_via_default_destroy(struct nb_cb_destroy_args *args)
{
	struct vrf *vrf;
	struct zebra_vrf *zvrf;
	bool resolve_via_default;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	vrf = nb_running_get_entry(args->dnode, NULL, true);
	zvrf = vrf->info;

	resolve_via_default = DFLT_ZEBRA_IP_NHT_RESOLVE_VIA_DEFAULT;

	if (zvrf->zebra_rnh_ip_default_route == resolve_via_default)
		return NB_OK;

	zvrf->zebra_rnh_ip_default_route = resolve_via_default;

	zebra_evaluate_rnh(zvrf, AFI_IP, 0, NULL, SAFI_UNICAST);

	return NB_OK;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:zebra/ipv6-resolve-via-default
 */
int lib_vrf_zebra_ipv6_resolve_via_default_modify(struct nb_cb_modify_args *args)
{
	struct vrf *vrf;
	struct zebra_vrf *zvrf;
	bool resolve_via_default;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	vrf = nb_running_get_entry(args->dnode, NULL, true);
	zvrf = vrf->info;

	resolve_via_default = yang_dnode_get_bool(args->dnode, NULL);

	if (zvrf->zebra_rnh_ipv6_default_route == resolve_via_default)
		return NB_OK;

	zvrf->zebra_rnh_ipv6_default_route = resolve_via_default;

	zebra_evaluate_rnh(zvrf, AFI_IP6, 0, NULL, SAFI_UNICAST);

	return NB_OK;
}

int lib_vrf_zebra_ipv6_resolve_via_default_destroy(struct nb_cb_destroy_args *args)
{
	struct vrf *vrf;
	struct zebra_vrf *zvrf;
	bool resolve_via_default;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	vrf = nb_running_get_entry(args->dnode, NULL, true);
	zvrf = vrf->info;

	resolve_via_default = DFLT_ZEBRA_IP_NHT_RESOLVE_VIA_DEFAULT;

	if (zvrf->zebra_rnh_ipv6_default_route == resolve_via_default)
		return NB_OK;

	zvrf->zebra_rnh_ipv6_default_route = resolve_via_default;

	zebra_evaluate_rnh(zvrf, AFI_IP6, 0, NULL, SAFI_UNICAST);

	return NB_OK;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:zebra/netns/table-range
 */
static int table_range_validate(uint32_t start, uint32_t end, char *errmsg,
				size_t errmsg_len)
{
#if defined(GNU_LINUX)
	if ((start >= RT_TABLE_ID_COMPAT && start <= RT_TABLE_ID_LOCAL) ||
	    (end >= RT_TABLE_ID_COMPAT && end <= RT_TABLE_ID_LOCAL)) {
		snprintfrr(errmsg, errmsg_len,
			   "Values forbidden in range [%u;%u]",
			   RT_TABLE_ID_COMPAT, RT_TABLE_ID_LOCAL);
		return NB_ERR_VALIDATION;
	}
	if (start < RT_TABLE_ID_COMPAT && end > RT_TABLE_ID_LOCAL) {
		snprintfrr(errmsg, errmsg_len,
			   "Range overlaps range [%u;%u] forbidden",
			   RT_TABLE_ID_COMPAT, RT_TABLE_ID_LOCAL);
		return NB_ERR_VALIDATION;
	}
#endif
	return NB_OK;
}

int lib_vrf_zebra_netns_table_range_create(struct nb_cb_create_args *args)
{
	struct vrf *vrf;
	uint32_t start, end;
	const char *vrf_name;

	start = yang_dnode_get_uint32(args->dnode, "start");
	end = yang_dnode_get_uint32(args->dnode, "end");

	if (args->event == NB_EV_VALIDATE) {
		vrf_name = yang_dnode_get_string(args->dnode, "../../../name");
		if (!vrf_is_backend_netns() &&
		    strcmp(vrf_name, VRF_DEFAULT_NAME)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "Configuration is not available in non-default VRFs when using VRF-lite backend.");
			return NB_ERR_VALIDATION;
		}
		return table_range_validate(start, end, args->errmsg,
					    args->errmsg_len);
	}

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	vrf = nb_running_get_entry(args->dnode, NULL, true);

	table_manager_range(true, vrf->info, start, end);

	return NB_OK;
}

int lib_vrf_zebra_netns_table_range_destroy(struct nb_cb_destroy_args *args)
{
	struct vrf *vrf;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	vrf = nb_running_get_entry(args->dnode, NULL, true);

	table_manager_range(false, vrf->info, 0, 0);

	return NB_OK;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:zebra/netns/table-range/start
 */
int lib_vrf_zebra_netns_table_range_start_modify(struct nb_cb_modify_args *args)
{
	struct vrf *vrf;
	uint32_t start, end;

	start = yang_dnode_get_uint32(args->dnode, NULL);
	end = yang_dnode_get_uint32(args->dnode, "../end");

	if (args->event == NB_EV_VALIDATE)
		return table_range_validate(start, end, args->errmsg,
					    args->errmsg_len);

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	vrf = nb_running_get_entry(args->dnode, NULL, true);

	table_manager_range(true, vrf->info, start, end);

	return NB_OK;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:zebra/netns/table-range/end
 */
int lib_vrf_zebra_netns_table_range_end_modify(struct nb_cb_modify_args *args)
{
	struct vrf *vrf;
	uint32_t start, end;

	start = yang_dnode_get_uint32(args->dnode, "../start");
	end = yang_dnode_get_uint32(args->dnode, NULL);

	if (args->event == NB_EV_VALIDATE)
		return table_range_validate(start, end, args->errmsg,
					    args->errmsg_len);

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	vrf = nb_running_get_entry(args->dnode, NULL, true);

	table_manager_range(true, vrf->info, start, end);

	return NB_OK;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:zebra/l3vni-id
 */
int lib_vrf_zebra_l3vni_id_modify(struct nb_cb_modify_args *args)
{
	struct vrf *vrf;
	vni_t vni = 0;
	bool pfx_only = false;
	uint32_t count;

	vni = yang_dnode_get_uint32(args->dnode, NULL);

	switch (args->event) {
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_VALIDATE:
		count = yang_dnode_count(args->dnode,
					 "/frr-vrf:lib/vrf/frr-zebra:zebra[l3vni-id='%u']",
					 vni);
		if (count > 1) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "vni %u is already mapped to another vrf",
				   vni);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		pfx_only = yang_dnode_get_bool(args->dnode, "../prefix-only");

		zebra_vxlan_process_vrf_vni_cmd(vrf->info, vni,
						pfx_only ? 1 : 0, 1);
		break;
	}

	return NB_OK;
}

int lib_vrf_zebra_l3vni_id_destroy(struct nb_cb_destroy_args *args)
{
	struct vrf *vrf;
	vni_t vni = 0;

	switch (args->event) {
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_VALIDATE:
		return NB_OK;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(args->dnode, NULL, true);
		vni = yang_dnode_get_uint32(args->dnode, NULL);

		zebra_vxlan_process_vrf_vni_cmd(vrf->info, vni, 0, 0);
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
