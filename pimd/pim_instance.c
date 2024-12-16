// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for FRR - PIM Instance
 * Copyright (C) 2017 Cumulus Networks, Inc.
 * Donald Sharp
 */
#include <zebra.h>

#include "hash.h"
#include "vrf.h"
#include "lib_errors.h"

#include "pimd.h"
#include "pim_instance.h"
#include "pim_ssm.h"
#include "pim_rpf.h"
#include "pim_rp.h"
#include "pim_mroute.h"
#include "pim_oil.h"
#include "pim_static.h"
#include "pim_ssmpingd.h"
#include "pim_vty.h"
#include "pim_bsm.h"
#include "pim_mlag.h"
#include "pim_sock.h"

static void pim_instance_terminate(struct pim_instance *pim)
{
	pim->stopping = true;

	pim_vxlan_exit(pim);

	if (pim->ssm_info) {
		pim_ssm_terminate(pim->ssm_info);
		pim->ssm_info = NULL;
	}

	if (pim->static_routes)
		list_delete(&pim->static_routes);

	pim_instance_mlag_terminate(pim);

	pim_upstream_terminate(pim);

	pim_rp_free(pim);

	pim_bsm_proc_free(pim);

	/* Traverse and cleanup rpf_hash */
	hash_clean_and_free(&pim->rpf_hash, (void *)pim_rp_list_hash_clean);

	pim_if_terminate(pim);

	pim_oil_terminate(pim);

#if PIM_IPV == 4
	pim_msdp_exit(pim);
#endif /* PIM_IPV == 4 */

	close(pim->reg_sock);

	pim_mroute_socket_disable(pim);

#if PIM_IPV == 4
	pim_autorp_finish(pim);
#endif

	XFREE(MTYPE_PIM_PLIST_NAME, pim->spt.plist);
	XFREE(MTYPE_PIM_PLIST_NAME, pim->register_plist);

	pim->vrf = NULL;
	XFREE(MTYPE_PIM_PIM_INSTANCE, pim);
}

static struct pim_instance *pim_instance_init(struct vrf *vrf)
{
	struct pim_instance *pim;
	char hash_name[64];

	pim = XCALLOC(MTYPE_PIM_PIM_INSTANCE, sizeof(struct pim_instance));

	pim_if_init(pim);

	pim->mcast_if_count = 0;
	pim->keep_alive_time = PIM_KEEPALIVE_PERIOD;
	pim->rp_keep_alive_time = PIM_RP_KEEPALIVE_PERIOD;

	pim->ecmp_enable = false;
	pim->ecmp_rebalance_enable = false;

	pim->vrf = vrf;

	pim->spt.switchover = PIM_SPT_IMMEDIATE;
	pim->spt.plist = NULL;

#if PIM_IPV == 4
	pim_msdp_init(pim, router->master);
#endif /* PIM_IPV == 4 */
	pim_vxlan_init(pim);

	snprintf(hash_name, sizeof(hash_name), "PIM %s RPF Hash", vrf->name);
	pim->rpf_hash = hash_create_size(256, pim_rpf_hash_key, pim_rpf_equal,
					 hash_name);

	if (PIM_DEBUG_ZEBRA)
		zlog_debug("%s: NHT rpf hash init ", __func__);

	pim->ssm_info = pim_ssm_init();

	pim->static_routes = list_new();
	pim->static_routes->del = (void (*)(void *))pim_static_route_free;

	pim->send_v6_secondary = 1;

	pim->gm_socket = -1;

	pim_rp_init(pim);

	pim_bsm_proc_init(pim);

	pim_oil_init(pim);

	pim_upstream_init(pim);

	pim_instance_mlag_init(pim);

	pim->last_route_change_time = -1;

	pim->reg_sock = pim_reg_sock();
	if (pim->reg_sock < 0)
		assert(0);

#if PIM_IPV == 4
	pim_autorp_init(pim);
#endif

	return pim;
}

struct pim_instance *pim_get_pim_instance(vrf_id_t vrf_id)
{
	struct vrf *vrf = vrf_lookup_by_id(vrf_id);

	if (vrf)
		return vrf->info;

	return NULL;
}

static int pim_vrf_new(struct vrf *vrf)
{
	struct pim_instance *pim = pim_instance_init(vrf);

	zlog_debug("VRF Created: %s(%u)", vrf->name, vrf->vrf_id);

	vrf->info = (void *)pim;

	pim_ssmpingd_init(pim);
	return 0;
}

static int pim_vrf_delete(struct vrf *vrf)
{
	struct pim_instance *pim = vrf->info;

	if (!pim)
		return 0;

	zlog_debug("VRF Deletion: %s(%u)", vrf->name, vrf->vrf_id);

	pim_ssmpingd_destroy(pim);
	pim_instance_terminate(pim);

	vrf->info = NULL;

	return 0;
}

/*
 * Code to turn on the pim instance that
 * we have created with new
 */
static int pim_vrf_enable(struct vrf *vrf)
{
	struct pim_instance *pim = (struct pim_instance *)vrf->info;
	struct interface *ifp;

	zlog_debug("%s: for %s %u", __func__, vrf->name, vrf->vrf_id);

	pim_mroute_socket_enable(pim);

	FOR_ALL_INTERFACES (vrf, ifp) {
		if (!ifp->info)
			continue;

		pim_if_create_pimreg(pim);
		break;
	}

	return 0;
}

static int pim_vrf_disable(struct vrf *vrf)
{
	/* Note: This is a callback, the VRF will be deleted by the caller. */
	return 0;
}

static int pim_vrf_config_write(struct vty *vty)
{
	struct vrf *vrf;
	struct pim_instance *pim;
	char spaces[10];

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		pim = vrf->info;

		if (!pim)
			continue;

		if (vrf->vrf_id != VRF_DEFAULT) {
			vty_frame(vty, "vrf %s\n", vrf->name);
			snprintf(spaces, sizeof(spaces), "%s", " ");
		} else {
			snprintf(spaces, sizeof(spaces), "%s", "");
		}

		/* Global IGMP/MLD configuration */
		if (pim->gm_watermark_limit != 0) {
#if PIM_IPV == 4
			vty_out(vty,
				"%s" PIM_AF_NAME " igmp watermark-warn %u\n",
				spaces, pim->gm_watermark_limit);
#else
			vty_out(vty, "%s" PIM_AF_NAME " mld watermark-warn %u\n",
				spaces, pim->gm_watermark_limit);
#endif
		}

		if (vrf->vrf_id != VRF_DEFAULT)
			vty_endframe(vty, "exit-vrf\n!\n");
	}

	return 0;
}

void pim_vrf_init(void)
{
	vrf_init(pim_vrf_new, pim_vrf_enable, pim_vrf_disable, pim_vrf_delete);

	vrf_cmd_init(pim_vrf_config_write);
}

void pim_vrf_terminate(void)
{
	struct vrf *vrf;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		struct pim_instance *pim;

		pim = vrf->info;
		if (!pim)
			continue;

		pim_crp_db_clear(&pim->global_scope);
		pim_ssmpingd_destroy(pim);
		pim_instance_terminate(pim);

		vrf->info = NULL;
	}

	vrf_terminate();
}

bool pim_msdp_log_neighbor_events(const struct pim_instance *pim)
{
	return (pim->log_flags & PIM_MSDP_LOG_NEIGHBOR_EVENTS);
}

bool pim_msdp_log_sa_events(const struct pim_instance *pim)
{
	return (pim->log_flags & PIM_MSDP_LOG_SA_EVENTS);
}
