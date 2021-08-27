/* Centralised Management Daemon program
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar
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


// #include "prefix.h"
#include "thread.h"
#include "buffer.h"
#include "stream.h"
#include "ringbuf.h"
#include "command.h"
#include "sockunion.h"
#include "sockopt.h"
#include "network.h"
#include "memory.h"
// #include "filter.h"
// #include "routemap.h"
#include "log.h"
#include "plist.h"
#include "linklist.h"
#include "workqueue.h"
#include "queue.h"
// #include "zclient.h"
// #include "bfd.h"
#include "hash.h"
#include "jhash.h"
#include "table.h"
#include "lib/json.h"
#include "frr_pthread.h"
#include "bitfield.h"

#include "cmgd/cmgd.h"
#include "cmgd/cmgd_vty.h"
#include "cmgd/cmgd_bcknd_server.h"
#include "cmgd/cmgd_bcknd_adapter.h"
#include "cmgd/cmgd_frntnd_server.h"
#include "cmgd/cmgd_frntnd_adapter.h"
#include "cmgd/cmgd_db.h"
#include "cmgd/cmgd_memory.h"

// DEFINE_MTYPE_STATIC(CMGDD, PEER_TX_SHUTDOWN_MSG, "Peer shutdown message (TX)");
// DEFINE_MTYPE_STATIC(CMGDD, CMGD_EVPN_INFO, "CMGD EVPN instance information");
// DEFINE_QOBJ_TYPE(cmgd_master)
// DEFINE_QOBJ_TYPE(cmgd)
// DEFINE_HOOK(cmgd_inst_delete, (struct cmgd *cmgd), (cmgd))

// bool cmgd_debug_bcknd = true;
// bool cmgd_debug_frntnd = true;
// bool cmgd_debug_db = true;
// bool cmgd_debug_trxn = true;
bool cmgd_debug_bcknd = false;
bool cmgd_debug_frntnd = false;
bool cmgd_debug_db = false;
bool cmgd_debug_trxn = false;

/* CMGD process wide configuration.  */
static struct cmgd_master cmgd_master;

/* CMGD process wide configuration pointer to export.  */
struct cmgd_master *cm;

#if 0
/* handle main socket creation or deletion */
static int cmgd_check_main_socket(bool create, struct cmgd *cmgd)
{
	static int cmgd_server_main_created;
	struct listnode *node;
	char *address;

	if (create) {
		if (cmgd_server_main_created)
			return 0;
		if (list_isempty(cm->addresses)) {
			if (cmgd_socket(cmgd, cm->port, NULL) < 0)
				return CMGD_ERR_INVALID_VALUE;
		} else {
			for (ALL_LIST_ELEMENTS_RO(cm->addresses, node, address))
				if (cmgd_socket(cmgd, cm->port, address) < 0)
					return CMGD_ERR_INVALID_VALUE;
		}
		cmgd_server_main_created = 1;
		return 0;
	}
	if (!cmgd_server_main_created)
		return 0;
	cmgd_close();
	cmgd_server_main_created = 0;
	return 0;
}


/* CMGD global flag manipulation.  */
int cmgd_option_set(int flag)
{
	switch (flag) {
	case CMGD_OPT_NO_FIB:
	case CMGD_OPT_NO_LISTEN:
	case CMGD_OPT_NO_ZEBRA:
		SET_FLAG(cm->options, flag);
		break;
	default:
		return CMGD_ERR_INVALID_FLAG;
	}
	return 0;
}

int cmgd_option_unset(int flag)
{
	switch (flag) {
	/* Fall through.  */
	case CMGD_OPT_NO_ZEBRA:
	case CMGD_OPT_NO_FIB:
		UNSET_FLAG(cm->options, flag);
		break;
	default:
		return CMGD_ERR_INVALID_FLAG;
	}
	return 0;
}

int cmgd_option_check(int flag)
{
	return CHECK_FLAG(cm->options, flag);
}

/* Internal function to set CMGD structure configureation flag.  */
static void cmgd_config_set(struct cmgd *cmgd, int config)
{
	SET_FLAG(cmgd->config, config);
}

static void cmgd_config_unset(struct cmgd *cmgd, int config)
{
	UNSET_FLAG(cmgd->config, config);
}

static int cmgd_config_check(struct cmgd *cmgd, int config)
{
	return CHECK_FLAG(cmgd->config, config);
}
#endif

/* time_t value that is monotonicly increasing
 * and uneffected by adjustments to system clock
 */
time_t cmgd_clock(void)
{
	struct timeval tv;

	monotime(&tv);
	return tv.tv_sec;
}

#if 0
static int cmgd_startup_timer_expire(struct thread *thread)
{
	struct cmgd *cmgd;

	cmgd = THREAD_ARG(thread);
	cmgd->t_startup = NULL;

	return 0;
}

/*
 * On shutdown we call the cleanup function which
 * does a free of the link list nodes,  free up
 * the data we are pointing at too.
 */
static void cmgd_vrf_string_name_delete(void *data)
{
	char *vname = data;

	XFREE(MTYPE_TMP, vname);
}

/* CMGD instance creation by `router cmgd' commands. */
static struct cmgd *cmgd_create(as_t *as, const char *name,
			      enum cmgd_instance_type inst_type)
{
	struct cmgd *cmgd;
	afi_t afi;
	safi_t safi;

	if ((cmgd = XCALLOC(MTYPE_CMGD, sizeof(struct cmgd))) == NULL)
		return NULL;

	if (CMGD_DEBUG(zebra, ZEBRA)) {
		if (inst_type == CMGD_INSTANCE_TYPE_DEFAULT)
			zlog_debug("Creating Default VRF, AS %u", *as);
		else
			zlog_debug("Creating %s %s, AS %u",
				   (inst_type == CMGD_INSTANCE_TYPE_VRF)
					   ? "VRF"
					   : "VIEW",
				   name, *as);
	}

	/* Default the EVPN VRF to the default one */
	if (inst_type == CMGD_INSTANCE_TYPE_DEFAULT && !cmgd_master.cmgd_evpn) {
		cmgd_lock(cmgd);
		cm->cmgd_evpn = cmgd;
	}

	cmgd_lock(cmgd);

	cmgd_process_queue_init(cmgd);
	cmgd->heuristic_coalesce = true;
	cmgd->inst_type = inst_type;
	cmgd->vrf_id = (inst_type == CMGD_INSTANCE_TYPE_DEFAULT) ? VRF_DEFAULT
							       : VRF_UNKNOWN;
	// cmgd->peer_self = peer_new(cmgd);
	// XFREE(MTYPE_CMGD_PEER_HOST, cmgd->peer_self->host);
	// cmgd->peer_self->host =
	// 	XSTRDUP(MTYPE_CMGD_PEER_HOST, "Static announcement");
	// XFREE(MTYPE_CMGD_PEER_HOST, cmgd->peer_self->hostname);
	// if (cmd_hostname_get())
	// 	cmgd->peer_self->hostname =
	// 		XSTRDUP(MTYPE_CMGD_PEER_HOST, cmd_hostname_get());

	// XFREE(MTYPE_CMGD_PEER_HOST, cmgd->peer_self->domainname);
	// if (cmd_domainname_get())
	// 	cmgd->peer_self->domainname =
	// 		XSTRDUP(MTYPE_CMGD_PEER_HOST, cmd_domainname_get());
	// cmgd->peer = list_new();
	// cmgd->peer->cmp = (int (*)(void *, void *))peer_cmp;
	// cmgd->peerhash = hash_create(peer_hash_key_make, peer_hash_same,
	// 			    "CMGD Peer Hash");
	// cmgd->peerhash->max_size = CMGD_PEER_MAX_HASH_SIZE;

	// cmgd->group = list_new();
	// cmgd->group->cmp = (int (*)(void *, void *))peer_group_cmp;

	// FOREACH_AFI_SAFI (afi, safi) {
	// 	cmgd->route[afi][safi] = cmgd_table_init(cmgd, afi, safi);
	// 	cmgd->aggregate[afi][safi] = cmgd_table_init(cmgd, afi, safi);
	// 	cmgd->rib[afi][safi] = cmgd_table_init(cmgd, afi, safi);

	// 	/* Enable maximum-paths */
	// 	cmgd_maximum_paths_set(cmgd, afi, safi, CMGD_PEER_ECMGD,
	// 			      multipath_num, 0);
	// 	cmgd_maximum_paths_set(cmgd, afi, safi, CMGD_PEER_ICMGD,
	// 			      multipath_num, 0);
	// 	/* Initialize graceful restart info */
	// 	cmgd->gr_info[afi][safi].eor_required = 0;
	// 	cmgd->gr_info[afi][safi].eor_received = 0;
	// 	cmgd->gr_info[afi][safi].t_select_deferral = NULL;
	// 	cmgd->gr_info[afi][safi].t_route_select = NULL;
	// 	cmgd->gr_info[afi][safi].gr_deferred = 0;
	// }

	// cmgd->v_update_delay = cm->v_update_delay;
	// cmgd->v_establish_wait = cm->v_establish_wait;
	// cmgd->default_local_pref = CMGD_DEFAULT_LOCAL_PREF;
	// cmgd->default_subgroup_pkt_queue_max =
	// 	CMGD_DEFAULT_SUBGROUP_PKT_QUEUE_MAX;
	// cmgd_timers_unset(cmgd);
	// cmgd->restart_time = CMGD_DEFAULT_RESTART_TIME;
	// cmgd->stalepath_time = CMGD_DEFAULT_STALEPATH_TIME;
	// cmgd->select_defer_time = CMGD_DEFAULT_SELECT_DEFERRAL_TIME;
	// cmgd->rib_stale_time = CMGD_DEFAULT_RIB_STALE_TIME;
	// cmgd->dynamic_neighbors_limit = CMGD_DYNAMIC_NEIGHBORS_LIMIT_DEFAULT;
	// cmgd->dynamic_neighbors_count = 0;
	// cmgd->lb_ref_bw = CMGD_LINK_BW_REF_BW;
	// cmgd->lb_handling = CMGD_LINK_BW_ECMP;
	// cmgd->reject_as_sets = false;
	// cmgd_addpath_init_cmgd_data(&cmgd->tx_addpath);

	// cmgd->as = *as;

#ifdef ENABLE_CMGD_VNC
	if (inst_type != CMGD_INSTANCE_TYPE_VRF) {
		cmgd->rfapi = cmgd_rfapi_new(cmgd);
		assert(cmgd->rfapi);
		assert(cmgd->rfapi_cfg);
	}
#endif /* ENABLE_CMGD_VNC */

	// for (afi = AFI_IP; afi < AFI_MAX; afi++) {
	// 	cmgd->vpn_policy[afi].cmgd = cmgd;
	// 	cmgd->vpn_policy[afi].afi = afi;
	// 	cmgd->vpn_policy[afi].tovpn_label = MPLS_LABEL_NONE;
	// 	cmgd->vpn_policy[afi].tovpn_zebra_vrf_label_last_sent =
	// 		MPLS_LABEL_NONE;

	// 	cmgd->vpn_policy[afi].import_vrf = list_new();
	// 	cmgd->vpn_policy[afi].import_vrf->del =
	// 		cmgd_vrf_string_name_delete;
	// 	cmgd->vpn_policy[afi].export_vrf = list_new();
	// 	cmgd->vpn_policy[afi].export_vrf->del =
	// 		cmgd_vrf_string_name_delete;
	// }
	if (name)
		cmgd->name = XSTRDUP(MTYPE_CMGD, name);

	thread_add_timer(cm->master, cmgd_startup_timer_expire, cmgd,
			 cmgd->restart_time, &cmgd->t_startup);

	/* printable name we can use in debug messages */
	if (inst_type == CMGD_INSTANCE_TYPE_DEFAULT) {
		cmgd->name_pretty = XSTRDUP(MTYPE_CMGD, "VRF default");
	} else {
		const char *n;
		int len;

		if (cmgd->name)
			n = cmgd->name;
		else
			n = "?";

		len = 4 + 1 + strlen(n) + 1;	/* "view foo\0" */

		cmgd->name_pretty = XCALLOC(MTYPE_CMGD, len);
		snprintf(cmgd->name_pretty, len, "%s %s",
			(cmgd->inst_type == CMGD_INSTANCE_TYPE_VRF)
				? "VRF"
				: "VIEW",
			n);
	}

	// atomic_store_explicit(&cmgd->wpkt_quanta, CMGD_WRITE_PACKET_MAX,
	// 		      memory_order_relaxed);
	// atomic_store_explicit(&cmgd->rpkt_quanta, CMGD_READ_PACKET_MAX,
	// 		      memory_order_relaxed);
	// cmgd->coalesce_time = CMGD_DEFAULT_SUBGROUP_COALESCE_TIME;

	// QOBJ_REG(cmgd, cmgd);

	// update_cmgd_group_init(cmgd);

	// /* assign a unique rd id for auto derivation of vrf's RD */
	// bf_assign_index(cm->rd_idspace, cmgd->vrf_rd_id);

	// cmgd->evpn_info = XCALLOC(MTYPE_CMGD_EVPN_INFO,
	// 			 sizeof(struct cmgd_evpn_info));

	// cmgd_evpn_init(cmgd);
	// cmgd_evpn_vrf_es_init(cmgd);
	// cmgd_pbr_init(cmgd);

	/*initilize global GR FSM */
	// cmgd_global_gr_init(cmgd);
	return cmgd;
}

/* Return the "default VRF" instance of CMGD. */
struct cmgd *cmgd_get_default(void)
{
	struct cmgd *cmgd;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(cm->cmgd, node, nnode, cmgd))
		if (cmgd->inst_type == CMGD_INSTANCE_TYPE_DEFAULT)
			return cmgd;
	return NULL;
}

/* Lookup CMGD entry. */
struct cmgd *cmgd_lookup(as_t as, const char *name)
{
	struct cmgd *cmgd;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(cm->cmgd, node, nnode, cmgd))
		if (cmgd->as == as
		    && ((cmgd->name == NULL && name == NULL)
			|| (cmgd->name && name && strcmp(cmgd->name, name) == 0)))
			return cmgd;
	return NULL;
}

/* Lookup CMGD structure by view name. */
struct cmgd *cmgd_lookup_by_name(const char *name)
{
	struct cmgd *cmgd;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(cm->cmgd, node, nnode, cmgd))
		if ((cmgd->name == NULL && name == NULL)
		    || (cmgd->name && name && strcmp(cmgd->name, name) == 0))
			return cmgd;
	return NULL;
}

/* Lookup CMGD instance based on VRF id. */
/* Note: Only to be used for incoming messages from Zebra. */
struct cmgd *cmgd_lookup_by_vrf_id(vrf_id_t vrf_id)
{
	struct vrf *vrf;

	/* Lookup VRF (in tree) and follow link. */
	vrf = vrf_lookup_by_id(vrf_id);
	if (!vrf)
		return NULL;
	return (vrf->info) ? (struct cmgd *)vrf->info : NULL;
}

/* Sets the CMGD instance where EVPN is enabled */
void cmgd_set_evpn(struct cmgd *cmgd)
{
	if (cm->cmgd_evpn == cmgd)
		return;

	/* First, release the reference count we hold on the instance */
	if (cm->cmgd_evpn)
		cmgd_unlock(cm->cmgd_evpn);

	cm->cmgd_evpn = cmgd;

	/* Increase the reference count on this new VRF */
	if (cm->cmgd_evpn)
		cmgd_lock(cm->cmgd_evpn);
}

/* Returns the CMGD instance where EVPN is enabled, if any */
struct cmgd *cmgd_get_evpn(void)
{
	return cm->cmgd_evpn;
}

/* handle socket creation or deletion, if necessary
 * this is called for all new CMGD instances
 */
int cmgd_handle_socket(struct cmgd *cmgd, struct vrf *vrf, vrf_id_t old_vrf_id,
		      bool create)
{
	struct listnode *node;
	char *address;

	/* Create CMGD server socket, if listen mode not disabled */
	if (!cmgd || cmgd_option_check(CMGD_OPT_NO_LISTEN))
		return 0;
	if (cmgd->inst_type == CMGD_INSTANCE_TYPE_VRF) {
		/*
		 * suppress vrf socket
		 */
		if (!create) {
			cmgd_close_vrf_socket(cmgd);
			return 0;
		}
		if (vrf == NULL)
			return CMGD_ERR_INVALID_VALUE;
		/* do nothing
		 * if vrf_id did not change
		 */
		if (vrf->vrf_id == old_vrf_id)
			return 0;
		if (old_vrf_id != VRF_UNKNOWN) {
			/* look for old socket. close it. */
			cmgd_close_vrf_socket(cmgd);
		}
		/* if backend is not yet identified ( VRF_UNKNOWN) then
		 *   creation will be done later
		 */
		if (vrf->vrf_id == VRF_UNKNOWN)
			return 0;
		if (list_isempty(cm->addresses)) {
			if (cmgd_socket(cmgd, cm->port, NULL) < 0)
				return CMGD_ERR_INVALID_VALUE;
		} else {
			for (ALL_LIST_ELEMENTS_RO(cm->addresses, node, address))
				if (cmgd_socket(cmgd, cm->port, address) < 0)
					return CMGD_ERR_INVALID_VALUE;
		}
		return 0;
	} else
		return cmgd_check_main_socket(create, cmgd);
}

int cmgd_lookup_by_as_name_type(struct cmgd **cmgd_val, as_t *as, const char *name,
			       enum cmgd_instance_type inst_type)
{
	struct cmgd *cmgd;

	/* Multiple instance check. */
	if (name)
		cmgd = cmgd_lookup_by_name(name);
	else
		cmgd = cmgd_get_default();

	if (cmgd) {
		if (cmgd->as != *as) {
			*as = cmgd->as;
			return CMGD_ERR_INSTANCE_MISMATCH;
		}
		if (cmgd->inst_type != inst_type)
			return CMGD_ERR_INSTANCE_MISMATCH;
		*cmgd_val = cmgd;
		return CMGD_SUCCESS;
	}
	*cmgd_val = NULL;

	return CMGD_SUCCESS;
}

/* Called from VTY commands. */
int cmgd_get(struct cmgd **cmgd_val, as_t *as, const char *name,
	    enum cmgd_instance_type inst_type)
{
	struct cmgd *cmgd;
	struct vrf *vrf = NULL;
	int ret = 0;

	ret = cmgd_lookup_by_as_name_type(cmgd_val, as, name, inst_type);
	switch (ret) {
	case CMGD_ERR_INSTANCE_MISMATCH:
		return ret;
	case CMGD_SUCCESS:
		if (*cmgd_val)
			return ret;
	}

	cmgd = cmgd_create(as, name, inst_type);
	if (cmgd_option_check(CMGD_OPT_NO_ZEBRA) && name)
		cmgd->vrf_id = vrf_generate_id();
	cmgd_router_id_set(cmgd, &cmgd->router_id_zebra, true);
	cmgd_address_init(cmgd);
	cmgd_tip_hash_init(cmgd);
	cmgd_scan_init(cmgd);
	*cmgd_val = cmgd;

	cmgd->t_rmap_def_originate_eval = NULL;

	/* If Default instance or VRF, link to the VRF structure, if present. */
	if (cmgd->inst_type == CMGD_INSTANCE_TYPE_DEFAULT
	    || cmgd->inst_type == CMGD_INSTANCE_TYPE_VRF) {
		vrf = cmgd_vrf_lookup_by_instance_type(cmgd);
		if (vrf)
			cmgd_vrf_link(cmgd, vrf);
	}
	/* CMGD server socket already processed if CMGD instance
	 * already part of the list
	 */
	cmgd_handle_socket(cmgd, vrf, VRF_UNKNOWN, true);
	listnode_add(cm->cmgd, cmgd);

	if (IS_CMGD_INST_KNOWN_TO_ZEBRA(cmgd)) {
		if (CMGD_DEBUG(zebra, ZEBRA))
			zlog_debug("%s: Registering CMGD instance %s to zebra",
				   __func__, name);
		cmgd_zebra_instance_register(cmgd);
	}

	return CMGD_CREATED;
}

/*
 * Make CMGD instance "up". Applies only to VRFs (non-default) and
 * implies the VRF has been learnt from Zebra.
 */
void cmgd_instance_up(struct cmgd *cmgd)
{
	struct peer *peer;
	struct listnode *node, *next;

	/* Register with zebra. */
	cmgd_zebra_instance_register(cmgd);

	/* Kick off any peers that may have been configured. */
	for (ALL_LIST_ELEMENTS(cmgd->peer, node, next, peer)) {
		if (!CMGD_PEER_START_SUPPRESSED(peer))
			CMGD_EVENT_ADD(peer, CMGD_Start);
	}

	/* Process any networks that have been configured. */
	cmgd_static_add(cmgd);
}

/*
 * Make CMGD instance "down". Applies only to VRFs (non-default) and
 * implies the VRF has been deleted by Zebra.
 */
void cmgd_instance_down(struct cmgd *cmgd)
{
	struct peer *peer;
	struct listnode *node;
	struct listnode *next;

	/* Stop timers. */
	if (cmgd->t_rmap_def_originate_eval) {
		CMGD_TIMER_OFF(cmgd->t_rmap_def_originate_eval);
		cmgd_unlock(cmgd); /* TODO - This timer is started with a lock -
				    why? */
	}

	/* Bring down peers, so corresponding routes are purged. */
	for (ALL_LIST_ELEMENTS(cmgd->peer, node, next, peer)) {
		if (CMGD_IS_VALID_STATE_FOR_NOTIF(peer->status))
			cmgd_notify_send(peer, CMGD_NOTIFY_CEASE,
					CMGD_NOTIFY_CEASE_ADMIN_SHUTDOWN);
		else
			cmgd_session_reset(peer);
	}

	/* Purge network and redistributed routes. */
	cmgd_purge_static_redist_routes(cmgd);

	/* Cleanup registered nexthops (flags) */
	cmgd_cleanup_nexthops(cmgd);
}

/* Delete CMGD instance. */
int cmgd_delete(struct cmgd *cmgd)
{
	struct peer *peer;
	struct peer_group *group;
	struct listnode *node, *next;
	struct vrf *vrf;
	afi_t afi;
	safi_t safi;
	int i;
	struct graceful_restart_info *gr_info;

	assert(cmgd);

	/* make sure we withdraw any exported routes */
	vpn_leak_prechange(CMGD_VPN_POLICY_DIR_TOVPN, AFI_IP, cmgd_get_default(),
			   cmgd);
	vpn_leak_prechange(CMGD_VPN_POLICY_DIR_TOVPN, AFI_IP6, cmgd_get_default(),
			   cmgd);

	cmgd_vpn_leak_unimport(cmgd);

	hook_call(cmgd_inst_delete, cmgd);

	THREAD_OFF(cmgd->t_startup);
	THREAD_OFF(cmgd->t_maxmed_onstartup);
	THREAD_OFF(cmgd->t_update_delay);
	THREAD_OFF(cmgd->t_establish_wait);

	/* Set flag indicating cmgd instance delete in progress */
	SET_FLAG(cmgd->flags, CMGD_FLAG_DELETE_IN_PROGRESS);

	/* Delete the graceful restart info */
	FOREACH_AFI_SAFI (afi, safi) {
		struct thread *t;

		gr_info = &cmgd->gr_info[afi][safi];
		if (!gr_info)
			continue;

		CMGD_TIMER_OFF(gr_info->t_select_deferral);

		t = gr_info->t_route_select;
		if (t) {
			void *info = THREAD_ARG(t);

			XFREE(MTYPE_TMP, info);
		}
		CMGD_TIMER_OFF(gr_info->t_route_select);
	}

	/* Delete route flap dampening configuration */
	FOREACH_AFI_SAFI (afi, safi) {
		cmgd_damp_disable(cmgd, afi, safi);
	}

	if (CMGD_DEBUG(zebra, ZEBRA)) {
		if (cmgd->inst_type == CMGD_INSTANCE_TYPE_DEFAULT)
			zlog_debug("Deleting Default VRF");
		else
			zlog_debug("Deleting %s %s",
				   (cmgd->inst_type == CMGD_INSTANCE_TYPE_VRF)
					   ? "VRF"
					   : "VIEW",
				   cmgd->name);
	}

	/* unmap from RT list */
	cmgd_evpn_vrf_delete(cmgd);

	/* unmap cmgd vrf label */
	vpn_leak_zebra_vrf_label_withdraw(cmgd, AFI_IP);
	vpn_leak_zebra_vrf_label_withdraw(cmgd, AFI_IP6);

	/* Stop timers. */
	if (cmgd->t_rmap_def_originate_eval) {
		CMGD_TIMER_OFF(cmgd->t_rmap_def_originate_eval);
		cmgd_unlock(cmgd); /* TODO - This timer is started with a lock -
				    why? */
	}

	/* Inform peers we're going down. */
	for (ALL_LIST_ELEMENTS(cmgd->peer, node, next, peer)) {
		if (CMGD_IS_VALID_STATE_FOR_NOTIF(peer->status))
			cmgd_notify_send(peer, CMGD_NOTIFY_CEASE,
					CMGD_NOTIFY_CEASE_ADMIN_SHUTDOWN);
	}

	/* Delete static routes (networks). */
	cmgd_static_delete(cmgd);

	/* Unset redistribution. */
	for (afi = AFI_IP; afi < AFI_MAX; afi++)
		for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
			if (i != ZEBRA_ROUTE_CMGD)
				cmgd_redistribute_unset(cmgd, afi, i, 0);

	/* Free peers and peer-groups. */
	for (ALL_LIST_ELEMENTS(cmgd->group, node, next, group))
		peer_group_delete(group);

	for (ALL_LIST_ELEMENTS(cmgd->peer, node, next, peer))
		peer_delete(peer);

	if (cmgd->peer_self) {
		peer_delete(cmgd->peer_self);
		cmgd->peer_self = NULL;
	}

	update_cmgd_group_free(cmgd);

/* TODO - Other memory may need to be freed - e.g., NHT */

#ifdef ENABLE_CMGD_VNC
	rfapi_delete(cmgd);
#endif
	cmgd_cleanup_routes(cmgd);

	for (afi = 0; afi < AFI_MAX; ++afi) {
		if (!cmgd->vpn_policy[afi].import_redirect_rtlist)
			continue;
		ecommunity_free(
				&cmgd->vpn_policy[afi]
				.import_redirect_rtlist);
		cmgd->vpn_policy[afi].import_redirect_rtlist = NULL;
	}

	/* Deregister from Zebra, if needed */
	if (IS_CMGD_INST_KNOWN_TO_ZEBRA(cmgd)) {
		if (CMGD_DEBUG(zebra, ZEBRA))
			zlog_debug(
				"%s: deregistering this cmgd %s instance from zebra",
				__func__, cmgd->name);
		cmgd_zebra_instance_deregister(cmgd);
	}

	/* Remove visibility via the master list - there may however still be
	 * routes to be processed still referencing the struct cmgd.
	 */
	listnode_delete(cm->cmgd, cmgd);

	/* Free interfaces in this instance. */
	cmgd_if_finish(cmgd);

	vrf = cmgd_vrf_lookup_by_instance_type(cmgd);
	cmgd_handle_socket(cmgd, vrf, VRF_UNKNOWN, false);
	if (vrf)
		cmgd_vrf_unlink(cmgd, vrf);

	/* Update EVPN VRF pointer */
	if (cm->cmgd_evpn == cmgd) {
		if (cmgd->inst_type == CMGD_INSTANCE_TYPE_DEFAULT)
			cmgd_set_evpn(NULL);
		else
			cmgd_set_evpn(cmgd_get_default());
	}

	if (cmgd->process_queue)
		work_queue_free_and_null(&cmgd->process_queue);

	thread_master_free_unused(cm->master);
	cmgd_unlock(cmgd); /* initial reference */

	return 0;
}

void cmgd_free(struct cmgd *cmgd)
{
	afi_t afi;
	safi_t safi;
	struct cmgd_table *table;
	struct cmgd_dest *dest;
	struct cmgd_rmap *rmap;

	QOBJ_UNREG(cmgd);

	list_delete(&cmgd->group);
	list_delete(&cmgd->peer);

	if (cmgd->peerhash) {
		hash_free(cmgd->peerhash);
		cmgd->peerhash = NULL;
	}

	FOREACH_AFI_SAFI (afi, safi) {
		/* Special handling for 2-level routing tables. */
		if (safi == SAFI_MPLS_VPN || safi == SAFI_ENCAP
		    || safi == SAFI_EVPN) {
			for (dest = cmgd_table_top(cmgd->rib[afi][safi]); dest;
			     dest = cmgd_route_next(dest)) {
				table = cmgd_dest_get_cmgd_table_info(dest);
				cmgd_table_finish(&table);
			}
		}
		if (cmgd->route[afi][safi])
			cmgd_table_finish(&cmgd->route[afi][safi]);
		if (cmgd->aggregate[afi][safi])
			cmgd_table_finish(&cmgd->aggregate[afi][safi]);
		if (cmgd->rib[afi][safi])
			cmgd_table_finish(&cmgd->rib[afi][safi]);
		rmap = &cmgd->table_map[afi][safi];
		XFREE(MTYPE_ROUTE_MAP_NAME, rmap->name);
	}

	cmgd_scan_finish(cmgd);
	cmgd_address_destroy(cmgd);
	cmgd_tip_hash_destroy(cmgd);

	/* release the auto RD id */
	bf_release_index(cm->rd_idspace, cmgd->vrf_rd_id);

	cmgd_evpn_cleanup(cmgd);
	cmgd_pbr_cleanup(cmgd);
	XFREE(MTYPE_CMGD_EVPN_INFO, cmgd->evpn_info);

	for (afi = AFI_IP; afi < AFI_MAX; afi++) {
		vpn_policy_direction_t dir;

		if (cmgd->vpn_policy[afi].import_vrf)
			list_delete(&cmgd->vpn_policy[afi].import_vrf);
		if (cmgd->vpn_policy[afi].export_vrf)
			list_delete(&cmgd->vpn_policy[afi].export_vrf);

		dir = CMGD_VPN_POLICY_DIR_FROMVPN;
		if (cmgd->vpn_policy[afi].rtlist[dir])
			ecommunity_free(&cmgd->vpn_policy[afi].rtlist[dir]);
		dir = CMGD_VPN_POLICY_DIR_TOVPN;
		if (cmgd->vpn_policy[afi].rtlist[dir])
			ecommunity_free(&cmgd->vpn_policy[afi].rtlist[dir]);
	}

	XFREE(MTYPE_CMGD, cmgd->name);
	XFREE(MTYPE_CMGD, cmgd->name_pretty);

	XFREE(MTYPE_CMGD, cmgd);
}

struct peer *peer_lookup_by_conf_if(struct cmgd *cmgd, const char *conf_if)
{
	struct peer *peer;
	struct listnode *node, *nnode;

	if (!conf_if)
		return NULL;

	if (cmgd != NULL) {
		for (ALL_LIST_ELEMENTS(cmgd->peer, node, nnode, peer))
			if (peer->conf_if && !strcmp(peer->conf_if, conf_if)
			    && !CHECK_FLAG(peer->sflags,
					   PEER_STATUS_ACCEPT_PEER))
				return peer;
	} else if (cm->cmgd != NULL) {
		struct listnode *cmgdnode, *ncmgdnode;

		for (ALL_LIST_ELEMENTS(cm->cmgd, cmgdnode, ncmgdnode, cmgd))
			for (ALL_LIST_ELEMENTS(cmgd->peer, node, nnode, peer))
				if (peer->conf_if
				    && !strcmp(peer->conf_if, conf_if)
				    && !CHECK_FLAG(peer->sflags,
						   PEER_STATUS_ACCEPT_PEER))
					return peer;
	}
	return NULL;
}

struct peer *peer_lookup_by_hostname(struct cmgd *cmgd, const char *hostname)
{
	struct peer *peer;
	struct listnode *node, *nnode;

	if (!hostname)
		return NULL;

	if (cmgd != NULL) {
		for (ALL_LIST_ELEMENTS(cmgd->peer, node, nnode, peer))
			if (peer->hostname && !strcmp(peer->hostname, hostname)
			    && !CHECK_FLAG(peer->sflags,
					   PEER_STATUS_ACCEPT_PEER))
				return peer;
	} else if (cm->cmgd != NULL) {
		struct listnode *cmgdnode, *ncmgdnode;

		for (ALL_LIST_ELEMENTS(cm->cmgd, cmgdnode, ncmgdnode, cmgd))
			for (ALL_LIST_ELEMENTS(cmgd->peer, node, nnode, peer))
				if (peer->hostname
				    && !strcmp(peer->hostname, hostname)
				    && !CHECK_FLAG(peer->sflags,
						   PEER_STATUS_ACCEPT_PEER))
					return peer;
	}
	return NULL;
}

struct peer *peer_lookup(struct cmgd *cmgd, union sockunion *su)
{
	struct peer *peer = NULL;
	struct peer tmp_peer;

	memset(&tmp_peer, 0, sizeof(struct peer));

	/*
	 * We do not want to find the doppelganger peer so search for the peer
	 * in
	 * the hash that has PEER_FLAG_CONFIG_NODE
	 */
	SET_FLAG(tmp_peer.flags, PEER_FLAG_CONFIG_NODE);

	tmp_peer.su = *su;

	if (cmgd != NULL) {
		peer = hash_lookup(cmgd->peerhash, &tmp_peer);
	} else if (cm->cmgd != NULL) {
		struct listnode *cmgdnode, *ncmgdnode;

		for (ALL_LIST_ELEMENTS(cm->cmgd, cmgdnode, ncmgdnode, cmgd)) {
			peer = hash_lookup(cmgd->peerhash, &tmp_peer);
			if (peer)
				break;
		}
	}

	return peer;
}

struct peer *peer_create_bind_dynamic_neighbor(struct cmgd *cmgd,
					       union sockunion *su,
					       struct peer_group *group)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	/* Create peer first; we've already checked group config is valid. */
	peer = peer_create(su, NULL, cmgd, cmgd->as, group->conf->as,
			   group->conf->as_type, 0, 0, group);
	if (!peer)
		return NULL;

	/* Link to group */
	peer = peer_lock(peer);
	listnode_add(group->peer, peer);

	peer_group2peer_config_copy(group, peer);

	/*
	 * Bind peer for all AFs configured for the group. We don't call
	 * peer_group_bind as that is sub-optimal and does some stuff we don't
	 * want.
	 */
	FOREACH_AFI_SAFI (afi, safi) {
		if (!group->conf->afc[afi][safi])
			continue;
		peer->afc[afi][safi] = 1;

		if (!peer_af_find(peer, afi, safi))
			peer_af_create(peer, afi, safi);

		peer_group2peer_config_copy_af(group, peer, afi, safi);
	}

	/* Mark as dynamic, but also as a "config node" for other things to
	 * work. */
	SET_FLAG(peer->flags, PEER_FLAG_DYNAMIC_NEIGHBOR);
	SET_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE);

	return peer;
}

struct prefix *
peer_group_lookup_dynamic_neighbor_range(struct peer_group *group,
					 struct prefix *prefix)
{
	struct listnode *node, *nnode;
	struct prefix *range;
	afi_t afi;

	afi = family2afi(prefix->family);

	if (group->listen_range[afi])
		for (ALL_LIST_ELEMENTS(group->listen_range[afi], node, nnode,
				       range))
			if (prefix_match(range, prefix))
				return range;

	return NULL;
}

struct peer_group *
peer_group_lookup_dynamic_neighbor(struct cmgd *cmgd, struct prefix *prefix,
				   struct prefix **listen_range)
{
	struct prefix *range = NULL;
	struct peer_group *group = NULL;
	struct listnode *node, *nnode;

	*listen_range = NULL;
	if (cmgd != NULL) {
		for (ALL_LIST_ELEMENTS(cmgd->group, node, nnode, group))
			if ((range = peer_group_lookup_dynamic_neighbor_range(
				     group, prefix)))
				break;
	} else if (cm->cmgd != NULL) {
		struct listnode *cmgdnode, *ncmgdnode;

		for (ALL_LIST_ELEMENTS(cm->cmgd, cmgdnode, ncmgdnode, cmgd))
			for (ALL_LIST_ELEMENTS(cmgd->group, node, nnode, group))
				if ((range = peer_group_lookup_dynamic_neighbor_range(
					     group, prefix)))
					goto found_range;
	}

found_range:
	*listen_range = range;
	return (group && range) ? group : NULL;
}

struct peer *peer_lookup_dynamic_neighbor(struct cmgd *cmgd, union sockunion *su)
{
	struct peer_group *group;
	struct cmgd *gcmgd;
	struct peer *peer;
	struct prefix prefix;
	struct prefix *listen_range;
	int dncount;
	char buf[PREFIX2STR_BUFFER];

	if (!sockunion2hostprefix(su, &prefix))
		return NULL;

	/* See if incoming connection matches a configured listen range. */
	group = peer_group_lookup_dynamic_neighbor(cmgd, &prefix, &listen_range);

	if (!group)
		return NULL;


	gcmgd = group->cmgd;

	if (!gcmgd)
		return NULL;

	prefix2str(&prefix, buf, sizeof(buf));

	if (cmgd_debug_neighbor_events(NULL))
		zlog_debug(
			"Dynamic Neighbor %s matches group %s listen range %pFX",
			buf, group->name, listen_range);

	/* Are we within the listen limit? */
	dncount = gcmgd->dynamic_neighbors_count;

	if (dncount >= gcmgd->dynamic_neighbors_limit) {
		if (cmgd_debug_neighbor_events(NULL))
			zlog_debug("Dynamic Neighbor %s rejected - at limit %d",
				   inet_sutop(su, buf),
				   gcmgd->dynamic_neighbors_limit);
		return NULL;
	}

	/* Ensure group is not disabled. */
	if (CHECK_FLAG(group->conf->flags, PEER_FLAG_SHUTDOWN)) {
		if (cmgd_debug_neighbor_events(NULL))
			zlog_debug(
				"Dynamic Neighbor %s rejected - group %s disabled",
				buf, group->name);
		return NULL;
	}

	/* Check that at least one AF is activated for the group. */
	if (!peer_group_af_configured(group)) {
		if (cmgd_debug_neighbor_events(NULL))
			zlog_debug(
				"Dynamic Neighbor %s rejected - no AF activated for group %s",
				buf, group->name);
		return NULL;
	}

	/* Create dynamic peer and bind to associated group. */
	peer = peer_create_bind_dynamic_neighbor(gcmgd, su, group);
	assert(peer);

	gcmgd->dynamic_neighbors_count = ++dncount;

	if (cmgd_debug_neighbor_events(peer))
		zlog_debug("%s Dynamic Neighbor added, group %s count %d",
			   peer->host, group->name, dncount);

	return peer;
}

static void peer_drop_dynamic_neighbor(struct peer *peer)
{
	int dncount = -1;
	if (peer->group->cmgd) {
		dncount = peer->group->cmgd->dynamic_neighbors_count;
		if (dncount)
			peer->group->cmgd->dynamic_neighbors_count = --dncount;
	}
	if (cmgd_debug_neighbor_events(peer))
		zlog_debug("%s dropped from group %s, count %d", peer->host,
			   peer->group->name, dncount);
}

/* If peer is configured at least one address family return 1. */
bool peer_active(struct peer *peer)
{
	if (CMGD_PEER_SU_UNSPEC(peer))
		return false;
	if (peer->afc[AFI_IP][SAFI_UNICAST] || peer->afc[AFI_IP][SAFI_MULTICAST]
	    || peer->afc[AFI_IP][SAFI_LABELED_UNICAST]
	    || peer->afc[AFI_IP][SAFI_MPLS_VPN] || peer->afc[AFI_IP][SAFI_ENCAP]
	    || peer->afc[AFI_IP][SAFI_FLOWSPEC]
	    || peer->afc[AFI_IP6][SAFI_UNICAST]
	    || peer->afc[AFI_IP6][SAFI_MULTICAST]
	    || peer->afc[AFI_IP6][SAFI_LABELED_UNICAST]
	    || peer->afc[AFI_IP6][SAFI_MPLS_VPN]
	    || peer->afc[AFI_IP6][SAFI_ENCAP]
	    || peer->afc[AFI_IP6][SAFI_FLOWSPEC]
	    || peer->afc[AFI_L2VPN][SAFI_EVPN])
		return true;
	return false;
}

/* If peer is negotiated at least one address family return 1. */
bool peer_active_nego(struct peer *peer)
{
	if (peer->afc_nego[AFI_IP][SAFI_UNICAST]
	    || peer->afc_nego[AFI_IP][SAFI_MULTICAST]
	    || peer->afc_nego[AFI_IP][SAFI_LABELED_UNICAST]
	    || peer->afc_nego[AFI_IP][SAFI_MPLS_VPN]
	    || peer->afc_nego[AFI_IP][SAFI_ENCAP]
	    || peer->afc_nego[AFI_IP][SAFI_FLOWSPEC]
	    || peer->afc_nego[AFI_IP6][SAFI_UNICAST]
	    || peer->afc_nego[AFI_IP6][SAFI_MULTICAST]
	    || peer->afc_nego[AFI_IP6][SAFI_LABELED_UNICAST]
	    || peer->afc_nego[AFI_IP6][SAFI_MPLS_VPN]
	    || peer->afc_nego[AFI_IP6][SAFI_ENCAP]
	    || peer->afc_nego[AFI_IP6][SAFI_FLOWSPEC]
	    || peer->afc_nego[AFI_L2VPN][SAFI_EVPN])
		return true;
	return false;
}

void peer_change_action(struct peer *peer, afi_t afi, safi_t safi,
			       enum peer_change_type type)
{
	struct peer_af *paf;

	if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP))
		return;

	if (peer->status != Established)
		return;

	if (type == peer_change_reset) {
		/* If we're resetting session, we've to delete both peer struct
		 */
		if ((peer->doppelganger)
		    && (peer->doppelganger->status != Deleted)
		    && (!CHECK_FLAG(peer->doppelganger->flags,
				    PEER_FLAG_CONFIG_NODE)))
			peer_delete(peer->doppelganger);

		cmgd_notify_send(peer, CMGD_NOTIFY_CEASE,
				CMGD_NOTIFY_CEASE_CONFIG_CHANGE);
	} else if (type == peer_change_reset_in) {
		if (CHECK_FLAG(peer->cap, PEER_CAP_REFRESH_OLD_RCV)
		    || CHECK_FLAG(peer->cap, PEER_CAP_REFRESH_NEW_RCV))
			cmgd_route_refresh_send(peer, afi, safi, 0, 0, 0,
					       CMGD_ROUTE_REFRESH_NORMAL);
		else {
			if ((peer->doppelganger)
			    && (peer->doppelganger->status != Deleted)
			    && (!CHECK_FLAG(peer->doppelganger->flags,
					    PEER_FLAG_CONFIG_NODE)))
				peer_delete(peer->doppelganger);

			cmgd_notify_send(peer, CMGD_NOTIFY_CEASE,
					CMGD_NOTIFY_CEASE_CONFIG_CHANGE);
		}
	} else if (type == peer_change_reset_out) {
		paf = peer_af_find(peer, afi, safi);
		if (paf && paf->subgroup)
			SET_FLAG(paf->subgroup->sflags,
				 SUBGRP_STATUS_FORCE_UPDATES);

		update_group_adjust_peer(paf);
		cmgd_announce_route(peer, afi, safi);
	}
}

struct peer_flag_action {
	/* Peer's flag.  */
	uint32_t flag;

	/* This flag can be set for peer-group member.  */
	uint8_t not_for_member;

	/* Action when the flag is changed.  */
	enum peer_change_type type;
};

static const struct peer_flag_action peer_flag_action_list[] = {
	{PEER_FLAG_PASSIVE, 0, peer_change_reset},
	{PEER_FLAG_SHUTDOWN, 0, peer_change_reset},
	{PEER_FLAG_RTT_SHUTDOWN, 0, peer_change_none},
	{PEER_FLAG_DONT_CAPABILITY, 0, peer_change_none},
	{PEER_FLAG_OVERRIDE_CAPABILITY, 0, peer_change_none},
	{PEER_FLAG_STRICT_CAP_MATCH, 0, peer_change_none},
	{PEER_FLAG_DYNAMIC_CAPABILITY, 0, peer_change_reset},
	{PEER_FLAG_DISABLE_CONNECTED_CHECK, 0, peer_change_reset},
	{PEER_FLAG_CAPABILITY_ENHE, 0, peer_change_reset},
	{PEER_FLAG_ENFORCE_FIRST_AS, 0, peer_change_reset_in},
	{PEER_FLAG_IFPEER_V6ONLY, 0, peer_change_reset},
	{PEER_FLAG_ROUTEADV, 0, peer_change_none},
	{PEER_FLAG_TIMER, 0, peer_change_none},
	{PEER_FLAG_TIMER_CONNECT, 0, peer_change_none},
	{PEER_FLAG_TIMER_DELAYOPEN, 0, peer_change_none},
	{PEER_FLAG_PASSWORD, 0, peer_change_none},
	{PEER_FLAG_LOCAL_AS, 0, peer_change_none},
	{PEER_FLAG_LOCAL_AS_NO_PREPEND, 0, peer_change_none},
	{PEER_FLAG_LOCAL_AS_REPLACE_AS, 0, peer_change_none},
	{PEER_FLAG_UPDATE_SOURCE, 0, peer_change_none},
	{0, 0, 0}};

static const struct peer_flag_action peer_af_flag_action_list[] = {
	{PEER_FLAG_SEND_COMMUNITY, 1, peer_change_reset_out},
	{PEER_FLAG_SEND_EXT_COMMUNITY, 1, peer_change_reset_out},
	{PEER_FLAG_SEND_LARGE_COMMUNITY, 1, peer_change_reset_out},
	{PEER_FLAG_NEXTHOP_SELF, 1, peer_change_reset_out},
	{PEER_FLAG_REFLECTOR_CLIENT, 1, peer_change_reset},
	{PEER_FLAG_RSERVER_CLIENT, 1, peer_change_reset},
	{PEER_FLAG_SOFT_RECONFIG, 0, peer_change_reset_in},
	{PEER_FLAG_AS_PATH_UNCHANGED, 1, peer_change_reset_out},
	{PEER_FLAG_NEXTHOP_UNCHANGED, 1, peer_change_reset_out},
	{PEER_FLAG_MED_UNCHANGED, 1, peer_change_reset_out},
	{PEER_FLAG_DEFAULT_ORIGINATE, 0, peer_change_none},
	{PEER_FLAG_REMOVE_PRIVATE_AS, 1, peer_change_reset_out},
	{PEER_FLAG_ALLOWAS_IN, 0, peer_change_reset_in},
	{PEER_FLAG_ALLOWAS_IN_ORIGIN, 0, peer_change_reset_in},
	{PEER_FLAG_ORF_PREFIX_SM, 1, peer_change_reset},
	{PEER_FLAG_ORF_PREFIX_RM, 1, peer_change_reset},
	{PEER_FLAG_MAX_PREFIX, 0, peer_change_none},
	{PEER_FLAG_MAX_PREFIX_WARNING, 0, peer_change_none},
	{PEER_FLAG_MAX_PREFIX_FORCE, 0, peer_change_none},
	{PEER_FLAG_NEXTHOP_LOCAL_UNCHANGED, 0, peer_change_reset_out},
	{PEER_FLAG_FORCE_NEXTHOP_SELF, 1, peer_change_reset_out},
	{PEER_FLAG_REMOVE_PRIVATE_AS_ALL, 1, peer_change_reset_out},
	{PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE, 1, peer_change_reset_out},
	{PEER_FLAG_AS_OVERRIDE, 1, peer_change_reset_out},
	{PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE, 1, peer_change_reset_out},
	{PEER_FLAG_WEIGHT, 0, peer_change_reset_in},
	{0, 0, 0}};

/* Proper action set. */
static int peer_flag_action_set(const struct peer_flag_action *action_list,
				int size, struct peer_flag_action *action,
				uint32_t flag)
{
	int i;
	int found = 0;
	int reset_in = 0;
	int reset_out = 0;
	const struct peer_flag_action *match = NULL;

	/* Check peer's frag action.  */
	for (i = 0; i < size; i++) {
		match = &action_list[i];

		if (match->flag == 0)
			break;

		if (match->flag & flag) {
			found = 1;

			if (match->type == peer_change_reset_in)
				reset_in = 1;
			if (match->type == peer_change_reset_out)
				reset_out = 1;
			if (match->type == peer_change_reset) {
				reset_in = 1;
				reset_out = 1;
			}
			if (match->not_for_member)
				action->not_for_member = 1;
		}
	}

	/* Set peer clear type.  */
	if (reset_in && reset_out)
		action->type = peer_change_reset;
	else if (reset_in)
		action->type = peer_change_reset_in;
	else if (reset_out)
		action->type = peer_change_reset_out;
	else
		action->type = peer_change_none;

	return found;
}

static void peer_flag_modify_action(struct peer *peer, uint32_t flag)
{
	if (flag == PEER_FLAG_SHUTDOWN) {
		if (CHECK_FLAG(peer->flags, flag)) {
			if (CHECK_FLAG(peer->sflags, PEER_STATUS_NSF_WAIT))
				peer_nsf_stop(peer);

			UNSET_FLAG(peer->sflags, PEER_STATUS_PREFIX_OVERFLOW);

			if (peer->t_pmax_restart) {
				CMGD_TIMER_OFF(peer->t_pmax_restart);
				if (cmgd_debug_neighbor_events(peer))
					zlog_debug(
						"%s Maximum-prefix restart timer canceled",
						peer->host);
			}

			if (CMGD_IS_VALID_STATE_FOR_NOTIF(peer->status)) {
				char *msg = peer->tx_shutdown_message;
				size_t msglen;

				if (!msg && peer_group_active(peer))
					msg = peer->group->conf
						      ->tx_shutdown_message;
				msglen = msg ? strlen(msg) : 0;
				if (msglen > 128)
					msglen = 128;

				if (msglen) {
					uint8_t msgbuf[129];

					msgbuf[0] = msglen;
					memcpy(msgbuf + 1, msg, msglen);

					cmgd_notify_send_with_data(
						peer, CMGD_NOTIFY_CEASE,
						CMGD_NOTIFY_CEASE_ADMIN_SHUTDOWN,
						msgbuf, msglen + 1);
				} else
					cmgd_notify_send(
						peer, CMGD_NOTIFY_CEASE,
						CMGD_NOTIFY_CEASE_ADMIN_SHUTDOWN);
			} else
				cmgd_session_reset(peer);
		} else {
			peer->v_start = CMGD_INIT_START_TIMER;
			CMGD_EVENT_ADD(peer, CMGD_Stop);
		}
	} else if (CMGD_IS_VALID_STATE_FOR_NOTIF(peer->status)) {
		if (flag == PEER_FLAG_DYNAMIC_CAPABILITY)
			peer->last_reset = PEER_DOWN_CAPABILITY_CHANGE;
		else if (flag == PEER_FLAG_PASSIVE)
			peer->last_reset = PEER_DOWN_PASSIVE_CHANGE;
		else if (flag == PEER_FLAG_DISABLE_CONNECTED_CHECK)
			peer->last_reset = PEER_DOWN_MULTIHOP_CHANGE;

		cmgd_notify_send(peer, CMGD_NOTIFY_CEASE,
				CMGD_NOTIFY_CEASE_CONFIG_CHANGE);
	} else
		cmgd_session_reset(peer);
}

/* Enable global administrative shutdown of all peers of CMGD instance */
void cmgd_shutdown_enable(struct cmgd *cmgd, const char *msg)
{
	struct peer *peer;
	struct listnode *node;

	/* do nothing if already shut down */
	if (CHECK_FLAG(cmgd->flags, CMGD_FLAG_SHUTDOWN))
		return;

	/* informational log message */
	zlog_info("Enabled administrative shutdown on CMGD instance AS %u",
		  cmgd->as);

	/* iterate through peers of CMGD instance */
	for (ALL_LIST_ELEMENTS_RO(cmgd->peer, node, peer)) {
		/* continue, if peer is already in administrative shutdown. */
		if (CHECK_FLAG(peer->flags, PEER_FLAG_SHUTDOWN))
			continue;

		/* send a RFC 4486 notification message if necessary */
		if (CMGD_IS_VALID_STATE_FOR_NOTIF(peer->status)) {
			if (msg)
				cmgd_notify_send_with_data(
					peer, CMGD_NOTIFY_CEASE,
					CMGD_NOTIFY_CEASE_ADMIN_SHUTDOWN,
					(uint8_t *)(msg), strlen(msg));
			else
				cmgd_notify_send(
					peer, CMGD_NOTIFY_CEASE,
					CMGD_NOTIFY_CEASE_ADMIN_SHUTDOWN);
		}

		/* reset start timer to initial value */
		peer->v_start = CMGD_INIT_START_TIMER;

		/* trigger a RFC 4271 ManualStop event */
		CMGD_EVENT_ADD(peer, CMGD_Stop);
	}

	/* set the CMGD instances shutdown flag */
	SET_FLAG(cmgd->flags, CMGD_FLAG_SHUTDOWN);
}

/* Disable global administrative shutdown of all peers of CMGD instance */
void cmgd_shutdown_disable(struct cmgd *cmgd)
{
	/* do nothing if not shut down. */
	if (!CHECK_FLAG(cmgd->flags, CMGD_FLAG_SHUTDOWN))
		return;

	/* informational log message */
	zlog_info("Disabled administrative shutdown on CMGD instance AS %u",
		  cmgd->as);

	/* clear the CMGD instances shutdown flag */
	UNSET_FLAG(cmgd->flags, CMGD_FLAG_SHUTDOWN);
}

/* Change specified peer flag. */
static int peer_flag_modify(struct peer *peer, uint32_t flag, int set)
{
	int found;
	int size;
	bool invert, member_invert;
	struct peer *member;
	struct listnode *node, *nnode;
	struct peer_flag_action action;

	memset(&action, 0, sizeof(struct peer_flag_action));
	size = sizeof(peer_flag_action_list) / sizeof(struct peer_flag_action);

	invert = CHECK_FLAG(peer->flags_invert, flag);
	found = peer_flag_action_set(peer_flag_action_list, size, &action,
				     flag);

	/* Abort if no flag action exists. */
	if (!found)
		return CMGD_ERR_INVALID_FLAG;

	/* Check for flag conflict: STRICT_CAP_MATCH && OVERRIDE_CAPABILITY */
	if (set && CHECK_FLAG(peer->flags | flag, PEER_FLAG_STRICT_CAP_MATCH)
	    && CHECK_FLAG(peer->flags | flag, PEER_FLAG_OVERRIDE_CAPABILITY))
		return CMGD_ERR_PEER_FLAG_CONFLICT;

	/* Handle flag updates where desired state matches current state. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		if (set && CHECK_FLAG(peer->flags, flag)) {
			COND_FLAG(peer->flags_override, flag, !invert);
			return 0;
		}

		if (!set && !CHECK_FLAG(peer->flags, flag)) {
			COND_FLAG(peer->flags_override, flag, invert);
			return 0;
		}
	}

	/* Inherit from peer-group or set/unset flags accordingly. */
	if (peer_group_active(peer) && set == invert)
		peer_flag_inherit(peer, flag);
	else
		COND_FLAG(peer->flags, flag, set);

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		/* Update flag override state accordingly. */
		COND_FLAG(peer->flags_override, flag, set != invert);

		/*
		 * For the extended next-hop encoding flag we need to turn RAs
		 * on if flag is being set, but only turn RAs off if the flag
		 * is being unset on this peer and if this peer is a member of a
		 * peer-group, the peer-group also doesn't have the flag set.
		 */
		if (flag == PEER_FLAG_CAPABILITY_ENHE) {
			if (set) {
				cmgd_zebra_initiate_radv(peer->cmgd, peer);
			} else if (peer_group_active(peer)) {
				if (!CHECK_FLAG(peer->group->conf->flags, flag))
					cmgd_zebra_terminate_radv(peer->cmgd,
								 peer);
			} else
				cmgd_zebra_terminate_radv(peer->cmgd, peer);
		}

		/* Execute flag action on peer. */
		if (action.type == peer_change_reset)
			peer_flag_modify_action(peer, flag);

		/* Skip peer-group mechanics for regular peers. */
		return 0;
	}

	/*
	 * Update peer-group members, unless they are explicitely overriding
	 * peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->flags_override, flag))
			continue;

		/* Check if only member without group is inverted. */
		member_invert =
			CHECK_FLAG(member->flags_invert, flag) && !invert;

		/* Skip peers with equivalent configuration. */
		if (set != member_invert && CHECK_FLAG(member->flags, flag))
			continue;

		if (set == member_invert && !CHECK_FLAG(member->flags, flag))
			continue;

		/* Update flag on peer-group member. */
		COND_FLAG(member->flags, flag, set != member_invert);

		if (flag == PEER_FLAG_CAPABILITY_ENHE)
			set ? cmgd_zebra_initiate_radv(member->cmgd, member)
			    : cmgd_zebra_terminate_radv(member->cmgd, member);

		/* Execute flag action on peer-group member. */
		if (action.type == peer_change_reset)
			peer_flag_modify_action(member, flag);
	}

	return 0;
}

int peer_flag_set(struct peer *peer, uint32_t flag)
{
	return peer_flag_modify(peer, flag, 1);
}

int peer_flag_unset(struct peer *peer, uint32_t flag)
{
	return peer_flag_modify(peer, flag, 0);
}

static int peer_af_flag_modify(struct peer *peer, afi_t afi, safi_t safi,
			       uint32_t flag, bool set)
{
	int found;
	int size;
	bool invert, member_invert;
	struct peer *member;
	struct listnode *node, *nnode;
	struct peer_flag_action action;
	cmgd_peer_sort_t ptype;

	memset(&action, 0, sizeof(struct peer_flag_action));
	size = sizeof(peer_af_flag_action_list)
	       / sizeof(struct peer_flag_action);

	invert = CHECK_FLAG(peer->af_flags_invert[afi][safi], flag);
	found = peer_flag_action_set(peer_af_flag_action_list, size, &action,
				     flag);

	/* Abort if flag action exists. */
	if (!found)
		return CMGD_ERR_INVALID_FLAG;

	ptype = peer_sort(peer);
	/* Special check for reflector client.  */
	if (flag & PEER_FLAG_REFLECTOR_CLIENT && ptype != CMGD_PEER_ICMGD)
		return CMGD_ERR_NOT_INTERNAL_PEER;

	/* Special check for remove-private-AS.  */
	if (flag & PEER_FLAG_REMOVE_PRIVATE_AS && ptype == CMGD_PEER_ICMGD)
		return CMGD_ERR_REMOVE_PRIVATE_AS;

	/* as-override is not allowed for ICMGD peers */
	if (flag & PEER_FLAG_AS_OVERRIDE && ptype == CMGD_PEER_ICMGD)
		return CMGD_ERR_AS_OVERRIDE;

	/* Handle flag updates where desired state matches current state. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		if (set && CHECK_FLAG(peer->af_flags[afi][safi], flag)) {
			COND_FLAG(peer->af_flags_override[afi][safi], flag,
				  !invert);
			return 0;
		}

		if (!set && !CHECK_FLAG(peer->af_flags[afi][safi], flag)) {
			COND_FLAG(peer->af_flags_override[afi][safi], flag,
				  invert);
			return 0;
		}
	}

	/*
	 * For EVPN we implicitly set the NEXTHOP_UNCHANGED flag,
	 * if we are setting/unsetting flags which conflict with this flag
	 * handle accordingly
	 */
	if (afi == AFI_L2VPN && safi == SAFI_EVPN) {
		if (set) {

			/*
			 * if we are setting NEXTHOP_SELF, we need to unset the
			 * NEXTHOP_UNCHANGED flag
			 */
			if (CHECK_FLAG(flag, PEER_FLAG_NEXTHOP_SELF) ||
			    CHECK_FLAG(flag, PEER_FLAG_FORCE_NEXTHOP_SELF))
				UNSET_FLAG(peer->af_flags[afi][safi],
					   PEER_FLAG_NEXTHOP_UNCHANGED);
		} else {

			/*
			 * if we are unsetting NEXTHOP_SELF, we need to set the
			 * NEXTHOP_UNCHANGED flag to reset the defaults for EVPN
			 */
			if (CHECK_FLAG(flag, PEER_FLAG_NEXTHOP_SELF) ||
			    CHECK_FLAG(flag, PEER_FLAG_FORCE_NEXTHOP_SELF))
				SET_FLAG(peer->af_flags[afi][safi],
					 PEER_FLAG_NEXTHOP_UNCHANGED);
		}
	}

	/*
	 * If the peer is a route server client let's not
	 * muck with the nexthop on the way out the door
	 */
	if (flag & PEER_FLAG_RSERVER_CLIENT) {
		if (set)
			SET_FLAG(peer->af_flags[afi][safi],
				 PEER_FLAG_NEXTHOP_UNCHANGED);
		else
			UNSET_FLAG(peer->af_flags[afi][safi],
				   PEER_FLAG_NEXTHOP_UNCHANGED);
	}

	/* Inherit from peer-group or set/unset flags accordingly. */
	if (peer_group_active(peer) && set == invert)
		peer_af_flag_inherit(peer, afi, safi, flag);
	else
		COND_FLAG(peer->af_flags[afi][safi], flag, set);

	/* Execute action when peer is established.  */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)
	    && peer->status == Established) {
		if (!set && flag == PEER_FLAG_SOFT_RECONFIG)
			cmgd_clear_adj_in(peer, afi, safi);
		else {
			if (flag == PEER_FLAG_REFLECTOR_CLIENT)
				peer->last_reset = PEER_DOWN_RR_CLIENT_CHANGE;
			else if (flag == PEER_FLAG_RSERVER_CLIENT)
				peer->last_reset = PEER_DOWN_RS_CLIENT_CHANGE;
			else if (flag == PEER_FLAG_ORF_PREFIX_SM)
				peer->last_reset = PEER_DOWN_CAPABILITY_CHANGE;
			else if (flag == PEER_FLAG_ORF_PREFIX_RM)
				peer->last_reset = PEER_DOWN_CAPABILITY_CHANGE;

			peer_change_action(peer, afi, safi, action.type);
		}
	}

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		COND_FLAG(peer->af_flags_override[afi][safi], flag,
			  set != invert);
	} else {
		/*
		 * Update peer-group members, unless they are explicitely
		 * overriding peer-group configuration.
		 */
		for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode,
				       member)) {
			/* Skip peers with overridden configuration. */
			if (CHECK_FLAG(member->af_flags_override[afi][safi],
				       flag))
				continue;

			/* Check if only member without group is inverted. */
			member_invert =
				CHECK_FLAG(member->af_flags_invert[afi][safi],
					   flag)
				&& !invert;

			/* Skip peers with equivalent configuration. */
			if (set != member_invert
			    && CHECK_FLAG(member->af_flags[afi][safi], flag))
				continue;

			if (set == member_invert
			    && !CHECK_FLAG(member->af_flags[afi][safi], flag))
				continue;

			/* Update flag on peer-group member. */
			COND_FLAG(member->af_flags[afi][safi], flag,
				  set != member_invert);

			/* Execute flag action on peer-group member. */
			if (member->status == Established) {
				if (!set && flag == PEER_FLAG_SOFT_RECONFIG)
					cmgd_clear_adj_in(member, afi, safi);
				else {
					if (flag == PEER_FLAG_REFLECTOR_CLIENT)
						member->last_reset =
							PEER_DOWN_RR_CLIENT_CHANGE;
					else if (flag
						 == PEER_FLAG_RSERVER_CLIENT)
						member->last_reset =
							PEER_DOWN_RS_CLIENT_CHANGE;
					else if (flag
						 == PEER_FLAG_ORF_PREFIX_SM)
						member->last_reset =
							PEER_DOWN_CAPABILITY_CHANGE;
					else if (flag
						 == PEER_FLAG_ORF_PREFIX_RM)
						member->last_reset =
							PEER_DOWN_CAPABILITY_CHANGE;

					peer_change_action(member, afi, safi,
							   action.type);
				}
			}
		}
	}

	return 0;
}

int peer_af_flag_set(struct peer *peer, afi_t afi, safi_t safi, uint32_t flag)
{
	return peer_af_flag_modify(peer, afi, safi, flag, 1);
}

int peer_af_flag_unset(struct peer *peer, afi_t afi, safi_t safi, uint32_t flag)
{
	return peer_af_flag_modify(peer, afi, safi, flag, 0);
}


void peer_tx_shutdown_message_set(struct peer *peer, const char *msg)
{
	XFREE(MTYPE_PEER_TX_SHUTDOWN_MSG, peer->tx_shutdown_message);
	peer->tx_shutdown_message =
		msg ? XSTRDUP(MTYPE_PEER_TX_SHUTDOWN_MSG, msg) : NULL;
}

void peer_tx_shutdown_message_unset(struct peer *peer)
{
	XFREE(MTYPE_PEER_TX_SHUTDOWN_MSG, peer->tx_shutdown_message);
}


/* ECMGD multihop configuration. */
int peer_ecmgd_multihop_set(struct peer *peer, int ttl)
{
	struct peer_group *group;
	struct listnode *node, *nnode;
	struct peer *peer1;

	if (peer->sort == CMGD_PEER_ICMGD || peer->conf_if)
		return 0;

	/* is there anything to do? */
	if (peer->ttl == ttl)
		return 0;

	/* see comment in peer_ttl_security_hops_set() */
	if (ttl != MAXTTL) {
		if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
			group = peer->group;
			if (group->conf->gtsm_hops != CMGD_GTSM_HOPS_DISABLED)
				return CMGD_ERR_NO_ECMGD_MULTIHOP_WITH_TTLHACK;

			for (ALL_LIST_ELEMENTS(group->peer, node, nnode,
					       peer1)) {
				if (peer1->sort == CMGD_PEER_ICMGD)
					continue;

				if (peer1->gtsm_hops != CMGD_GTSM_HOPS_DISABLED)
					return CMGD_ERR_NO_ECMGD_MULTIHOP_WITH_TTLHACK;
			}
		} else {
			if (peer->gtsm_hops != CMGD_GTSM_HOPS_DISABLED)
				return CMGD_ERR_NO_ECMGD_MULTIHOP_WITH_TTLHACK;
		}
	}

	peer->ttl = ttl;

	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		if (peer->sort != CMGD_PEER_ICMGD) {
			if (CMGD_IS_VALID_STATE_FOR_NOTIF(peer->status))
				cmgd_notify_send(peer, CMGD_NOTIFY_CEASE,
						CMGD_NOTIFY_CEASE_CONFIG_CHANGE);
			else
				cmgd_session_reset(peer);
		}
	} else {
		group = peer->group;
		for (ALL_LIST_ELEMENTS(group->peer, node, nnode, peer)) {
			if (peer->sort == CMGD_PEER_ICMGD)
				continue;

			peer->ttl = group->conf->ttl;

			if (CMGD_IS_VALID_STATE_FOR_NOTIF(peer->status))
				cmgd_notify_send(peer, CMGD_NOTIFY_CEASE,
						CMGD_NOTIFY_CEASE_CONFIG_CHANGE);
			else
				cmgd_session_reset(peer);
		}
	}
	return 0;
}

int peer_ecmgd_multihop_unset(struct peer *peer)
{
	struct peer_group *group;
	struct listnode *node, *nnode;

	if (peer->sort == CMGD_PEER_ICMGD)
		return 0;

	if (peer->gtsm_hops != CMGD_GTSM_HOPS_DISABLED && peer->ttl != MAXTTL)
		return CMGD_ERR_NO_ECMGD_MULTIHOP_WITH_TTLHACK;

	if (peer_group_active(peer))
		peer->ttl = peer->group->conf->ttl;
	else
		peer->ttl = CMGD_DEFAULT_TTL;

	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		if (CMGD_IS_VALID_STATE_FOR_NOTIF(peer->status))
			cmgd_notify_send(peer, CMGD_NOTIFY_CEASE,
					CMGD_NOTIFY_CEASE_CONFIG_CHANGE);
		else
			cmgd_session_reset(peer);
	} else {
		group = peer->group;
		for (ALL_LIST_ELEMENTS(group->peer, node, nnode, peer)) {
			if (peer->sort == CMGD_PEER_ICMGD)
				continue;

			peer->ttl = CMGD_DEFAULT_TTL;

			if (peer->fd >= 0) {
				if (CMGD_IS_VALID_STATE_FOR_NOTIF(peer->status))
					cmgd_notify_send(
						peer, CMGD_NOTIFY_CEASE,
						CMGD_NOTIFY_CEASE_CONFIG_CHANGE);
				else
					cmgd_session_reset(peer);
			}
		}
	}
	return 0;
}

/* Neighbor description. */
void peer_description_set(struct peer *peer, const char *desc)
{
	XFREE(MTYPE_PEER_DESC, peer->desc);

	peer->desc = XSTRDUP(MTYPE_PEER_DESC, desc);
}

void peer_description_unset(struct peer *peer)
{
	XFREE(MTYPE_PEER_DESC, peer->desc);
}

/* Neighbor update-source. */
int peer_update_source_if_set(struct peer *peer, const char *ifname)
{
	struct peer *member;
	struct listnode *node, *nnode;

	/* Set flag and configuration on peer. */
	peer_flag_set(peer, PEER_FLAG_UPDATE_SOURCE);
	if (peer->update_if) {
		if (strcmp(peer->update_if, ifname) == 0)
			return 0;
		XFREE(MTYPE_PEER_UPDATE_SOURCE, peer->update_if);
	}
	peer->update_if = XSTRDUP(MTYPE_PEER_UPDATE_SOURCE, ifname);
	sockunion_free(peer->update_source);
	peer->update_source = NULL;

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		/* Send notification or reset peer depending on state. */
		if (CMGD_IS_VALID_STATE_FOR_NOTIF(peer->status)) {
			peer->last_reset = PEER_DOWN_UPDATE_SOURCE_CHANGE;
			cmgd_notify_send(peer, CMGD_NOTIFY_CEASE,
					CMGD_NOTIFY_CEASE_CONFIG_CHANGE);
		} else
			cmgd_session_reset(peer);

		/* Skip peer-group mechanics for regular peers. */
		return 0;
	}

	/*
	 * Set flag and configuration on all peer-group members, unless they are
	 * explicitely overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->flags_override, PEER_FLAG_UPDATE_SOURCE))
			continue;

		/* Skip peers with the same configuration. */
		if (member->update_if) {
			if (strcmp(member->update_if, ifname) == 0)
				continue;
			XFREE(MTYPE_PEER_UPDATE_SOURCE, member->update_if);
		}

		/* Set flag and configuration on peer-group member. */
		SET_FLAG(member->flags, PEER_FLAG_UPDATE_SOURCE);
		member->update_if = XSTRDUP(MTYPE_PEER_UPDATE_SOURCE, ifname);
		sockunion_free(member->update_source);
		member->update_source = NULL;

		/* Send notification or reset peer depending on state. */
		if (CMGD_IS_VALID_STATE_FOR_NOTIF(member->status)) {
			member->last_reset = PEER_DOWN_UPDATE_SOURCE_CHANGE;
			cmgd_notify_send(member, CMGD_NOTIFY_CEASE,
					CMGD_NOTIFY_CEASE_CONFIG_CHANGE);
		} else
			cmgd_session_reset(member);
	}

	return 0;
}

int peer_update_source_addr_set(struct peer *peer, const union sockunion *su)
{
	struct peer *member;
	struct listnode *node, *nnode;

	/* Set flag and configuration on peer. */
	peer_flag_set(peer, PEER_FLAG_UPDATE_SOURCE);
	if (peer->update_source) {
		if (sockunion_cmp(peer->update_source, su) == 0)
			return 0;
		sockunion_free(peer->update_source);
	}
	peer->update_source = sockunion_dup(su);
	XFREE(MTYPE_PEER_UPDATE_SOURCE, peer->update_if);

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		/* Send notification or reset peer depending on state. */
		if (CMGD_IS_VALID_STATE_FOR_NOTIF(peer->status)) {
			peer->last_reset = PEER_DOWN_UPDATE_SOURCE_CHANGE;
			cmgd_notify_send(peer, CMGD_NOTIFY_CEASE,
					CMGD_NOTIFY_CEASE_CONFIG_CHANGE);
		} else
			cmgd_session_reset(peer);

		/* Skip peer-group mechanics for regular peers. */
		return 0;
	}

	/*
	 * Set flag and configuration on all peer-group members, unless they are
	 * explicitely overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->flags_override, PEER_FLAG_UPDATE_SOURCE))
			continue;

		/* Skip peers with the same configuration. */
		if (member->update_source) {
			if (sockunion_cmp(member->update_source, su) == 0)
				continue;
			sockunion_free(member->update_source);
		}

		/* Set flag and configuration on peer-group member. */
		SET_FLAG(member->flags, PEER_FLAG_UPDATE_SOURCE);
		member->update_source = sockunion_dup(su);
		XFREE(MTYPE_PEER_UPDATE_SOURCE, member->update_if);

		/* Send notification or reset peer depending on state. */
		if (CMGD_IS_VALID_STATE_FOR_NOTIF(member->status)) {
			member->last_reset = PEER_DOWN_UPDATE_SOURCE_CHANGE;
			cmgd_notify_send(member, CMGD_NOTIFY_CEASE,
					CMGD_NOTIFY_CEASE_CONFIG_CHANGE);
		} else
			cmgd_session_reset(member);
	}

	return 0;
}

int peer_update_source_unset(struct peer *peer)
{
	struct peer *member;
	struct listnode *node, *nnode;

	if (!CHECK_FLAG(peer->flags, PEER_FLAG_UPDATE_SOURCE))
		return 0;

	/* Inherit configuration from peer-group if peer is member. */
	if (peer_group_active(peer)) {
		peer_flag_inherit(peer, PEER_FLAG_UPDATE_SOURCE);
		PEER_SU_ATTR_INHERIT(peer, peer->group, update_source);
		PEER_STR_ATTR_INHERIT(peer, peer->group, update_if,
				      MTYPE_PEER_UPDATE_SOURCE);
	} else {
		/* Otherwise remove flag and configuration from peer. */
		peer_flag_unset(peer, PEER_FLAG_UPDATE_SOURCE);
		sockunion_free(peer->update_source);
		peer->update_source = NULL;
		XFREE(MTYPE_PEER_UPDATE_SOURCE, peer->update_if);
	}

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		/* Send notification or reset peer depending on state. */
		if (CMGD_IS_VALID_STATE_FOR_NOTIF(peer->status)) {
			peer->last_reset = PEER_DOWN_UPDATE_SOURCE_CHANGE;
			cmgd_notify_send(peer, CMGD_NOTIFY_CEASE,
					CMGD_NOTIFY_CEASE_CONFIG_CHANGE);
		} else
			cmgd_session_reset(peer);

		/* Skip peer-group mechanics for regular peers. */
		return 0;
	}

	/*
	 * Set flag and configuration on all peer-group members, unless they are
	 * explicitely overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->flags_override, PEER_FLAG_UPDATE_SOURCE))
			continue;

		/* Skip peers with the same configuration. */
		if (!CHECK_FLAG(member->flags, PEER_FLAG_UPDATE_SOURCE)
		    && !member->update_source && !member->update_if)
			continue;

		/* Remove flag and configuration on peer-group member. */
		UNSET_FLAG(member->flags, PEER_FLAG_UPDATE_SOURCE);
		sockunion_free(member->update_source);
		member->update_source = NULL;
		XFREE(MTYPE_PEER_UPDATE_SOURCE, member->update_if);

		/* Send notification or reset peer depending on state. */
		if (CMGD_IS_VALID_STATE_FOR_NOTIF(member->status)) {
			member->last_reset = PEER_DOWN_UPDATE_SOURCE_CHANGE;
			cmgd_notify_send(member, CMGD_NOTIFY_CEASE,
					CMGD_NOTIFY_CEASE_CONFIG_CHANGE);
		} else
			cmgd_session_reset(member);
	}

	return 0;
}

int peer_default_originate_set(struct peer *peer, afi_t afi, safi_t safi,
			       const char *rmap, struct route_map *route_map)
{
	struct peer *member;
	struct listnode *node, *nnode;

	/* Set flag and configuration on peer. */
	peer_af_flag_set(peer, afi, safi, PEER_FLAG_DEFAULT_ORIGINATE);
	if (rmap) {
		if (!peer->default_rmap[afi][safi].name
		    || strcmp(rmap, peer->default_rmap[afi][safi].name) != 0) {
			if (peer->default_rmap[afi][safi].name)
				XFREE(MTYPE_ROUTE_MAP_NAME,
				      peer->default_rmap[afi][safi].name);

			route_map_counter_decrement(peer->default_rmap[afi][safi].map);
			peer->default_rmap[afi][safi].name =
				XSTRDUP(MTYPE_ROUTE_MAP_NAME, rmap);
			peer->default_rmap[afi][safi].map = route_map;
			route_map_counter_increment(route_map);
		}
	} else if (!rmap) {
		if (peer->default_rmap[afi][safi].name)
			XFREE(MTYPE_ROUTE_MAP_NAME,
			      peer->default_rmap[afi][safi].name);

		route_map_counter_decrement(peer->default_rmap[afi][safi].map);
		peer->default_rmap[afi][safi].name = NULL;
		peer->default_rmap[afi][safi].map = NULL;
	}

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		/* Update peer route announcements. */
		if (peer->status == Established && peer->afc_nego[afi][safi]) {
			update_group_adjust_peer(peer_af_find(peer, afi, safi));
			cmgd_default_originate(peer, afi, safi, 0);
			cmgd_announce_route(peer, afi, safi);
		}

		/* Skip peer-group mechanics for regular peers. */
		return 0;
	}

	/*
	 * Set flag and configuration on all peer-group members, unless they are
	 * explicitely overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->af_flags_override[afi][safi],
			       PEER_FLAG_DEFAULT_ORIGINATE))
			continue;

		/* Set flag and configuration on peer-group member. */
		SET_FLAG(member->af_flags[afi][safi],
			 PEER_FLAG_DEFAULT_ORIGINATE);
		if (rmap) {
			if (member->default_rmap[afi][safi].name)
				XFREE(MTYPE_ROUTE_MAP_NAME,
				      member->default_rmap[afi][safi].name);
			route_map_counter_decrement(
					member->default_rmap[afi][safi].map);
			member->default_rmap[afi][safi].name =
				XSTRDUP(MTYPE_ROUTE_MAP_NAME, rmap);
			member->default_rmap[afi][safi].map = route_map;
			route_map_counter_increment(route_map);
		}

		/* Update peer route announcements. */
		if (member->status == Established
		    && member->afc_nego[afi][safi]) {
			update_group_adjust_peer(
				peer_af_find(member, afi, safi));
			cmgd_default_originate(member, afi, safi, 0);
			cmgd_announce_route(member, afi, safi);
		}
	}

	return 0;
}

int peer_default_originate_unset(struct peer *peer, afi_t afi, safi_t safi)
{
	struct peer *member;
	struct listnode *node, *nnode;

	/* Inherit configuration from peer-group if peer is member. */
	if (peer_group_active(peer)) {
		peer_af_flag_inherit(peer, afi, safi,
				     PEER_FLAG_DEFAULT_ORIGINATE);
		PEER_STR_ATTR_INHERIT(peer, peer->group,
				      default_rmap[afi][safi].name,
				      MTYPE_ROUTE_MAP_NAME);
		PEER_ATTR_INHERIT(peer, peer->group,
				  default_rmap[afi][safi].map);
	} else {
		/* Otherwise remove flag and configuration from peer. */
		peer_af_flag_unset(peer, afi, safi,
				   PEER_FLAG_DEFAULT_ORIGINATE);
		if (peer->default_rmap[afi][safi].name)
			XFREE(MTYPE_ROUTE_MAP_NAME,
			      peer->default_rmap[afi][safi].name);
		route_map_counter_decrement(peer->default_rmap[afi][safi].map);
		peer->default_rmap[afi][safi].name = NULL;
		peer->default_rmap[afi][safi].map = NULL;
	}

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		/* Update peer route announcements. */
		if (peer->status == Established && peer->afc_nego[afi][safi]) {
			update_group_adjust_peer(peer_af_find(peer, afi, safi));
			cmgd_default_originate(peer, afi, safi, 1);
			cmgd_announce_route(peer, afi, safi);
		}

		/* Skip peer-group mechanics for regular peers. */
		return 0;
	}

	/*
	 * Remove flag and configuration from all peer-group members, unless
	 * they are explicitely overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->af_flags_override[afi][safi],
			       PEER_FLAG_DEFAULT_ORIGINATE))
			continue;

		/* Remove flag and configuration on peer-group member. */
		UNSET_FLAG(member->af_flags[afi][safi],
			   PEER_FLAG_DEFAULT_ORIGINATE);
		if (member->default_rmap[afi][safi].name)
			XFREE(MTYPE_ROUTE_MAP_NAME,
			      member->default_rmap[afi][safi].name);
		route_map_counter_decrement(member->default_rmap[afi][safi].map);
		member->default_rmap[afi][safi].name = NULL;
		member->default_rmap[afi][safi].map = NULL;

		/* Update peer route announcements. */
		if (member->status == Established && member->afc_nego[afi][safi]) {
			update_group_adjust_peer(peer_af_find(member, afi, safi));
			cmgd_default_originate(member, afi, safi, 1);
			cmgd_announce_route(member, afi, safi);
		}
	}

	return 0;
}

void peer_port_set(struct peer *peer, uint16_t port)
{
	peer->port = port;
}

void peer_port_unset(struct peer *peer)
{
	peer->port = CMGD_PORT_DEFAULT;
}

/*
 * Helper function that is called after the name of the policy
 * being used by a peer has changed (AF specific). Automatically
 * initiates inbound or outbound processing as needed.
 */
static void peer_on_policy_change(struct peer *peer, afi_t afi, safi_t safi,
				  int outbound)
{
	if (outbound) {
		update_group_adjust_peer(peer_af_find(peer, afi, safi));
		if (peer->status == Established)
			cmgd_announce_route(peer, afi, safi);
	} else {
		if (peer->status != Established)
			return;

		if (CHECK_FLAG(peer->af_flags[afi][safi],
			       PEER_FLAG_SOFT_RECONFIG))
			cmgd_soft_reconfig_in(peer, afi, safi);
		else if (CHECK_FLAG(peer->cap, PEER_CAP_REFRESH_OLD_RCV)
			 || CHECK_FLAG(peer->cap, PEER_CAP_REFRESH_NEW_RCV))
			cmgd_route_refresh_send(peer, afi, safi, 0, 0, 0,
					       CMGD_ROUTE_REFRESH_NORMAL);
	}
}


/* neighbor weight. */
int peer_weight_set(struct peer *peer, afi_t afi, safi_t safi, uint16_t weight)
{
	struct peer *member;
	struct listnode *node, *nnode;

	/* Set flag and configuration on peer. */
	peer_af_flag_set(peer, afi, safi, PEER_FLAG_WEIGHT);
	if (peer->weight[afi][safi] != weight) {
		peer->weight[afi][safi] = weight;
		peer_on_policy_change(peer, afi, safi, 0);
	}

	/* Skip peer-group mechanics for regular peers. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP))
		return 0;

	/*
	 * Set flag and configuration on all peer-group members, unless they are
	 * explicitely overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->af_flags_override[afi][safi],
			       PEER_FLAG_WEIGHT))
			continue;

		/* Set flag and configuration on peer-group member. */
		SET_FLAG(member->af_flags[afi][safi], PEER_FLAG_WEIGHT);
		if (member->weight[afi][safi] != weight) {
			member->weight[afi][safi] = weight;
			peer_on_policy_change(member, afi, safi, 0);
		}
	}

	return 0;
}

int peer_weight_unset(struct peer *peer, afi_t afi, safi_t safi)
{
	struct peer *member;
	struct listnode *node, *nnode;

	if (!CHECK_FLAG(peer->af_flags[afi][safi], PEER_FLAG_WEIGHT))
		return 0;

	/* Inherit configuration from peer-group if peer is member. */
	if (peer_group_active(peer)) {
		peer_af_flag_inherit(peer, afi, safi, PEER_FLAG_WEIGHT);
		PEER_ATTR_INHERIT(peer, peer->group, weight[afi][safi]);

		peer_on_policy_change(peer, afi, safi, 0);
		return 0;
	}

	/* Remove flag and configuration from peer. */
	peer_af_flag_unset(peer, afi, safi, PEER_FLAG_WEIGHT);
	peer->weight[afi][safi] = 0;
	peer_on_policy_change(peer, afi, safi, 0);

	/* Skip peer-group mechanics for regular peers. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP))
		return 0;

	/*
	 * Remove flag and configuration from all peer-group members, unless
	 * they are explicitely overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->af_flags_override[afi][safi],
			       PEER_FLAG_WEIGHT))
			continue;

		/* Skip peers where flag is already disabled. */
		if (!CHECK_FLAG(member->af_flags[afi][safi], PEER_FLAG_WEIGHT))
			continue;

		/* Remove flag and configuration on peer-group member. */
		UNSET_FLAG(member->af_flags[afi][safi], PEER_FLAG_WEIGHT);
		member->weight[afi][safi] = 0;
		peer_on_policy_change(member, afi, safi, 0);
	}

	return 0;
}

int peer_timers_set(struct peer *peer, uint32_t keepalive, uint32_t holdtime)
{
	struct peer *member;
	struct listnode *node, *nnode;

	if (keepalive > 65535)
		return CMGD_ERR_INVALID_VALUE;

	if (holdtime > 65535)
		return CMGD_ERR_INVALID_VALUE;

	if (holdtime < 3 && holdtime != 0)
		return CMGD_ERR_INVALID_VALUE;

	/* Set flag and configuration on peer. */
	peer_flag_set(peer, PEER_FLAG_TIMER);
	peer->holdtime = holdtime;
	peer->keepalive = (keepalive < holdtime / 3 ? keepalive : holdtime / 3);

	/* Skip peer-group mechanics for regular peers. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP))
		return 0;

	/*
	 * Set flag and configuration on all peer-group members, unless they are
	 * explicitely overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->flags_override, PEER_FLAG_TIMER))
			continue;

		/* Set flag and configuration on peer-group member. */
		SET_FLAG(member->flags, PEER_FLAG_TIMER);
		PEER_ATTR_INHERIT(peer, peer->group, holdtime);
		PEER_ATTR_INHERIT(peer, peer->group, keepalive);
	}

	return 0;
}

int peer_timers_unset(struct peer *peer)
{
	struct peer *member;
	struct listnode *node, *nnode;

	/* Inherit configuration from peer-group if peer is member. */
	if (peer_group_active(peer)) {
		peer_flag_inherit(peer, PEER_FLAG_TIMER);
		PEER_ATTR_INHERIT(peer, peer->group, holdtime);
		PEER_ATTR_INHERIT(peer, peer->group, keepalive);
	} else {
		/* Otherwise remove flag and configuration from peer. */
		peer_flag_unset(peer, PEER_FLAG_TIMER);
		peer->holdtime = 0;
		peer->keepalive = 0;
	}

	/* Skip peer-group mechanics for regular peers. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP))
		return 0;

	/*
	 * Remove flag and configuration from all peer-group members, unless
	 * they are explicitely overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->flags_override, PEER_FLAG_TIMER))
			continue;

		/* Remove flag and configuration on peer-group member. */
		UNSET_FLAG(member->flags, PEER_FLAG_TIMER);
		member->holdtime = 0;
		member->keepalive = 0;
	}

	return 0;
}

int peer_timers_connect_set(struct peer *peer, uint32_t connect)
{
	struct peer *member;
	struct listnode *node, *nnode;

	if (connect > 65535)
		return CMGD_ERR_INVALID_VALUE;

	/* Set flag and configuration on peer. */
	peer_flag_set(peer, PEER_FLAG_TIMER_CONNECT);
	peer->connect = connect;
	peer->v_connect = connect;

	/* Skip peer-group mechanics for regular peers. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP))
		return 0;

	/*
	 * Set flag and configuration on all peer-group members, unless they are
	 * explicitely overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->flags_override, PEER_FLAG_TIMER_CONNECT))
			continue;

		/* Set flag and configuration on peer-group member. */
		SET_FLAG(member->flags, PEER_FLAG_TIMER_CONNECT);
		member->connect = connect;
		member->v_connect = connect;
	}

	return 0;
}

int peer_timers_connect_unset(struct peer *peer)
{
	struct peer *member;
	struct listnode *node, *nnode;

	/* Inherit configuration from peer-group if peer is member. */
	if (peer_group_active(peer)) {
		peer_flag_inherit(peer, PEER_FLAG_TIMER_CONNECT);
		PEER_ATTR_INHERIT(peer, peer->group, connect);
	} else {
		/* Otherwise remove flag and configuration from peer. */
		peer_flag_unset(peer, PEER_FLAG_TIMER_CONNECT);
		peer->connect = 0;
	}

	/* Set timer with fallback to default value. */
	if (peer->connect)
		peer->v_connect = peer->connect;
	else
		peer->v_connect = peer->cmgd->default_connect_retry;

	/* Skip peer-group mechanics for regular peers. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP))
		return 0;

	/*
	 * Remove flag and configuration from all peer-group members, unless
	 * they are explicitely overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->flags_override, PEER_FLAG_TIMER_CONNECT))
			continue;

		/* Remove flag and configuration on peer-group member. */
		UNSET_FLAG(member->flags, PEER_FLAG_TIMER_CONNECT);
		member->connect = 0;
		member->v_connect = peer->cmgd->default_connect_retry;
	}

	return 0;
}

int peer_advertise_interval_set(struct peer *peer, uint32_t routeadv)
{
	struct peer *member;
	struct listnode *node, *nnode;

	if (routeadv > 600)
		return CMGD_ERR_INVALID_VALUE;

	/* Set flag and configuration on peer. */
	peer_flag_set(peer, PEER_FLAG_ROUTEADV);
	peer->routeadv = routeadv;
	peer->v_routeadv = routeadv;

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		/* Update peer route announcements. */
		update_group_adjust_peer_afs(peer);
		if (peer->status == Established)
			cmgd_announce_route_all(peer);

		/* Skip peer-group mechanics for regular peers. */
		return 0;
	}

	/*
	 * Set flag and configuration on all peer-group members, unless they are
	 * explicitely overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->flags_override, PEER_FLAG_ROUTEADV))
			continue;

		/* Set flag and configuration on peer-group member. */
		SET_FLAG(member->flags, PEER_FLAG_ROUTEADV);
		member->routeadv = routeadv;
		member->v_routeadv = routeadv;

		/* Update peer route announcements. */
		update_group_adjust_peer_afs(member);
		if (member->status == Established)
			cmgd_announce_route_all(member);
	}

	return 0;
}

int peer_advertise_interval_unset(struct peer *peer)
{
	struct peer *member;
	struct listnode *node, *nnode;

	/* Inherit configuration from peer-group if peer is member. */
	if (peer_group_active(peer)) {
		peer_flag_inherit(peer, PEER_FLAG_ROUTEADV);
		PEER_ATTR_INHERIT(peer, peer->group, routeadv);
	} else {
		/* Otherwise remove flag and configuration from peer. */
		peer_flag_unset(peer, PEER_FLAG_ROUTEADV);
		peer->routeadv = 0;
	}

	/* Set timer with fallback to default value. */
	if (peer->routeadv)
		peer->v_routeadv = peer->routeadv;
	else
		peer->v_routeadv = (peer->sort == CMGD_PEER_ICMGD)
					   ? CMGD_DEFAULT_ICMGD_ROUTEADV
					   : CMGD_DEFAULT_ECMGD_ROUTEADV;

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		/* Update peer route announcements. */
		update_group_adjust_peer_afs(peer);
		if (peer->status == Established)
			cmgd_announce_route_all(peer);

		/* Skip peer-group mechanics for regular peers. */
		return 0;
	}

	/*
	 * Remove flag and configuration from all peer-group members, unless
	 * they are explicitely overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->flags_override, PEER_FLAG_ROUTEADV))
			continue;

		/* Remove flag and configuration on peer-group member. */
		UNSET_FLAG(member->flags, PEER_FLAG_ROUTEADV);
		member->routeadv = 0;
		member->v_routeadv = (member->sort == CMGD_PEER_ICMGD)
					     ? CMGD_DEFAULT_ICMGD_ROUTEADV
					     : CMGD_DEFAULT_ECMGD_ROUTEADV;

		/* Update peer route announcements. */
		update_group_adjust_peer_afs(member);
		if (member->status == Established)
			cmgd_announce_route_all(member);
	}

	return 0;
}

/* set the peers RFC 4271 DelayOpen session attribute flag and DelayOpenTimer
 * interval
 */
int peer_timers_delayopen_set(struct peer *peer, uint32_t delayopen)
{
	struct peer *member;
	struct listnode *node;

	/* Set peers session attribute flag and timer interval. */
	peer_flag_set(peer, PEER_FLAG_TIMER_DELAYOPEN);
	peer->delayopen = delayopen;
	peer->v_delayopen = delayopen;

	/* Skip group mechanics for regular peers. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP))
		return 0;

	/* Set flag and configuration on all peer-group members, unless they are
	 * explicitely overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS_RO(peer->group->peer, node, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->flags_override,
			       PEER_FLAG_TIMER_DELAYOPEN))
			continue;

		/* Set session attribute flag and timer intervals on peer-group
		 * member.
		 */
		SET_FLAG(member->flags, PEER_FLAG_TIMER_DELAYOPEN);
		member->delayopen = delayopen;
		member->v_delayopen = delayopen;
	}

	return 0;
}

/* unset the peers RFC 4271 DelayOpen session attribute flag and reset the
 * DelayOpenTimer interval to the default value.
 */
int peer_timers_delayopen_unset(struct peer *peer)
{
	struct peer *member;
	struct listnode *node;

	/* Inherit configuration from peer-group if peer is member. */
	if (peer_group_active(peer)) {
		peer_flag_inherit(peer, PEER_FLAG_TIMER_DELAYOPEN);
		PEER_ATTR_INHERIT(peer, peer->group, delayopen);
	} else {
		/* Otherwise remove session attribute flag and set timer
		 * interval to default value.
		 */
		peer_flag_unset(peer, PEER_FLAG_TIMER_DELAYOPEN);
		peer->delayopen = peer->cmgd->default_delayopen;
	}

	/* Set timer value to zero */
	peer->v_delayopen = 0;

	/* Skip peer-group mechanics for regular peers. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP))
		return 0;

	/* Remove flag and configuration from all peer-group members, unless
	 * they are explicitely overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS_RO(peer->group->peer, node, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->flags_override,
			       PEER_FLAG_TIMER_DELAYOPEN))
			continue;

		/* Remove session attribute flag, reset the timer interval to
		 * the default value and set the timer value to zero.
		 */
		UNSET_FLAG(member->flags, PEER_FLAG_TIMER_DELAYOPEN);
		member->delayopen = peer->cmgd->default_delayopen;
		member->v_delayopen = 0;
	}

	return 0;
}

/* neighbor interface */
void peer_interface_set(struct peer *peer, const char *str)
{
	XFREE(MTYPE_CMGD_PEER_IFNAME, peer->ifname);
	peer->ifname = XSTRDUP(MTYPE_CMGD_PEER_IFNAME, str);
}

void peer_interface_unset(struct peer *peer)
{
	XFREE(MTYPE_CMGD_PEER_IFNAME, peer->ifname);
}

/* Allow-as in.  */
int peer_allowas_in_set(struct peer *peer, afi_t afi, safi_t safi,
			int allow_num, int origin)
{
	struct peer *member;
	struct listnode *node, *nnode;

	if (!origin && (allow_num < 1 || allow_num > 10))
		return CMGD_ERR_INVALID_VALUE;

	/* Set flag and configuration on peer. */
	peer_af_flag_set(peer, afi, safi, PEER_FLAG_ALLOWAS_IN);
	if (origin) {
		if (peer->allowas_in[afi][safi] != 0
		    || !CHECK_FLAG(peer->af_flags[afi][safi],
				   PEER_FLAG_ALLOWAS_IN_ORIGIN)) {
			peer_af_flag_set(peer, afi, safi,
					 PEER_FLAG_ALLOWAS_IN_ORIGIN);
			peer->allowas_in[afi][safi] = 0;
			peer_on_policy_change(peer, afi, safi, 0);
		}
	} else {
		if (peer->allowas_in[afi][safi] != allow_num
		    || CHECK_FLAG(peer->af_flags[afi][safi],
				  PEER_FLAG_ALLOWAS_IN_ORIGIN)) {

			peer_af_flag_unset(peer, afi, safi,
					   PEER_FLAG_ALLOWAS_IN_ORIGIN);
			peer->allowas_in[afi][safi] = allow_num;
			peer_on_policy_change(peer, afi, safi, 0);
		}
	}

	/* Skip peer-group mechanics for regular peers. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP))
		return 0;

	/*
	 * Set flag and configuration on all peer-group members, unless
	 * they are explicitely overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->af_flags_override[afi][safi],
			       PEER_FLAG_ALLOWAS_IN))
			continue;

		/* Set flag and configuration on peer-group member. */
		SET_FLAG(member->af_flags[afi][safi], PEER_FLAG_ALLOWAS_IN);
		if (origin) {
			if (member->allowas_in[afi][safi] != 0
			    || !CHECK_FLAG(member->af_flags[afi][safi],
					   PEER_FLAG_ALLOWAS_IN_ORIGIN)) {
				SET_FLAG(member->af_flags[afi][safi],
					 PEER_FLAG_ALLOWAS_IN_ORIGIN);
				member->allowas_in[afi][safi] = 0;
				peer_on_policy_change(peer, afi, safi, 0);
			}
		} else {
			if (member->allowas_in[afi][safi] != allow_num
			    || CHECK_FLAG(member->af_flags[afi][safi],
					  PEER_FLAG_ALLOWAS_IN_ORIGIN)) {
				UNSET_FLAG(member->af_flags[afi][safi],
					   PEER_FLAG_ALLOWAS_IN_ORIGIN);
				member->allowas_in[afi][safi] = allow_num;
				peer_on_policy_change(peer, afi, safi, 0);
			}
		}
	}

	return 0;
}

int peer_allowas_in_unset(struct peer *peer, afi_t afi, safi_t safi)
{
	struct peer *member;
	struct listnode *node, *nnode;

	/* Skip peer if flag is already disabled. */
	if (!CHECK_FLAG(peer->af_flags[afi][safi], PEER_FLAG_ALLOWAS_IN))
		return 0;

	/* Inherit configuration from peer-group if peer is member. */
	if (peer_group_active(peer)) {
		peer_af_flag_inherit(peer, afi, safi, PEER_FLAG_ALLOWAS_IN);
		peer_af_flag_inherit(peer, afi, safi,
				     PEER_FLAG_ALLOWAS_IN_ORIGIN);
		PEER_ATTR_INHERIT(peer, peer->group, allowas_in[afi][safi]);
		peer_on_policy_change(peer, afi, safi, 0);

		return 0;
	}

	/* Remove flag and configuration from peer. */
	peer_af_flag_unset(peer, afi, safi, PEER_FLAG_ALLOWAS_IN);
	peer_af_flag_unset(peer, afi, safi, PEER_FLAG_ALLOWAS_IN_ORIGIN);
	peer->allowas_in[afi][safi] = 0;
	peer_on_policy_change(peer, afi, safi, 0);

	/* Skip peer-group mechanics if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP))
		return 0;

	/*
	 * Remove flags and configuration from all peer-group members, unless
	 * they are explicitely overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->af_flags_override[afi][safi],
			       PEER_FLAG_ALLOWAS_IN))
			continue;

		/* Skip peers where flag is already disabled. */
		if (!CHECK_FLAG(member->af_flags[afi][safi],
				PEER_FLAG_ALLOWAS_IN))
			continue;

		/* Remove flags and configuration on peer-group member. */
		UNSET_FLAG(member->af_flags[afi][safi], PEER_FLAG_ALLOWAS_IN);
		UNSET_FLAG(member->af_flags[afi][safi],
			   PEER_FLAG_ALLOWAS_IN_ORIGIN);
		member->allowas_in[afi][safi] = 0;
		peer_on_policy_change(member, afi, safi, 0);
	}

	return 0;
}

int peer_local_as_set(struct peer *peer, as_t as, bool no_prepend,
		      bool replace_as)
{
	bool old_no_prepend, old_replace_as;
	struct cmgd *cmgd = peer->cmgd;
	struct peer *member;
	struct listnode *node, *nnode;
	cmgd_peer_sort_t ptype = peer_sort(peer);

	if (ptype != CMGD_PEER_ECMGD && ptype != CMGD_PEER_INTERNAL)
		return CMGD_ERR_LOCAL_AS_ALLOWED_ONLY_FOR_ECMGD;

	if (cmgd->as == as)
		return CMGD_ERR_CANNOT_HAVE_LOCAL_AS_SAME_AS;

	if (peer->as == as)
		return CMGD_ERR_CANNOT_HAVE_LOCAL_AS_SAME_AS_REMOTE_AS;

	/* Save previous flag states. */
	old_no_prepend =
		!!CHECK_FLAG(peer->flags, PEER_FLAG_LOCAL_AS_NO_PREPEND);
	old_replace_as =
		!!CHECK_FLAG(peer->flags, PEER_FLAG_LOCAL_AS_REPLACE_AS);

	/* Set flag and configuration on peer. */
	peer_flag_set(peer, PEER_FLAG_LOCAL_AS);
	peer_flag_modify(peer, PEER_FLAG_LOCAL_AS_NO_PREPEND, no_prepend);
	peer_flag_modify(peer, PEER_FLAG_LOCAL_AS_REPLACE_AS, replace_as);

	if (peer->change_local_as == as && old_no_prepend == no_prepend
	    && old_replace_as == replace_as)
		return 0;
	peer->change_local_as = as;

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		/* Send notification or reset peer depending on state. */
		if (CMGD_IS_VALID_STATE_FOR_NOTIF(peer->status)) {
			peer->last_reset = PEER_DOWN_LOCAL_AS_CHANGE;
			cmgd_notify_send(peer, CMGD_NOTIFY_CEASE,
					CMGD_NOTIFY_CEASE_CONFIG_CHANGE);
		} else
			cmgd_session_reset(peer);

		/* Skip peer-group mechanics for regular peers. */
		return 0;
	}

	/*
	 * Set flag and configuration on all peer-group members, unless they are
	 * explicitely overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->flags_override, PEER_FLAG_LOCAL_AS))
			continue;

		/* Skip peers with the same configuration. */
		old_no_prepend = CHECK_FLAG(member->flags,
					    PEER_FLAG_LOCAL_AS_NO_PREPEND);
		old_replace_as = CHECK_FLAG(member->flags,
					    PEER_FLAG_LOCAL_AS_REPLACE_AS);
		if (member->change_local_as == as
		    && CHECK_FLAG(member->flags, PEER_FLAG_LOCAL_AS)
		    && old_no_prepend == no_prepend
		    && old_replace_as == replace_as)
			continue;

		/* Set flag and configuration on peer-group member. */
		SET_FLAG(member->flags, PEER_FLAG_LOCAL_AS);
		COND_FLAG(member->flags, PEER_FLAG_LOCAL_AS_NO_PREPEND,
			  no_prepend);
		COND_FLAG(member->flags, PEER_FLAG_LOCAL_AS_REPLACE_AS,
			  replace_as);
		member->change_local_as = as;

		/* Send notification or stop peer depending on state. */
		if (CMGD_IS_VALID_STATE_FOR_NOTIF(member->status)) {
			member->last_reset = PEER_DOWN_LOCAL_AS_CHANGE;
			cmgd_notify_send(member, CMGD_NOTIFY_CEASE,
					CMGD_NOTIFY_CEASE_CONFIG_CHANGE);
		} else
			CMGD_EVENT_ADD(member, CMGD_Stop);
	}

	return 0;
}

int peer_local_as_unset(struct peer *peer)
{
	struct peer *member;
	struct listnode *node, *nnode;

	if (!CHECK_FLAG(peer->flags, PEER_FLAG_LOCAL_AS))
		return 0;

	/* Inherit configuration from peer-group if peer is member. */
	if (peer_group_active(peer)) {
		peer_flag_inherit(peer, PEER_FLAG_LOCAL_AS);
		peer_flag_inherit(peer, PEER_FLAG_LOCAL_AS_NO_PREPEND);
		peer_flag_inherit(peer, PEER_FLAG_LOCAL_AS_REPLACE_AS);
		PEER_ATTR_INHERIT(peer, peer->group, change_local_as);
	} else {
		/* Otherwise remove flag and configuration from peer. */
		peer_flag_unset(peer, PEER_FLAG_LOCAL_AS);
		peer_flag_unset(peer, PEER_FLAG_LOCAL_AS_NO_PREPEND);
		peer_flag_unset(peer, PEER_FLAG_LOCAL_AS_REPLACE_AS);
		peer->change_local_as = 0;
	}

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		/* Send notification or stop peer depending on state. */
		if (CMGD_IS_VALID_STATE_FOR_NOTIF(peer->status)) {
			peer->last_reset = PEER_DOWN_LOCAL_AS_CHANGE;
			cmgd_notify_send(peer, CMGD_NOTIFY_CEASE,
					CMGD_NOTIFY_CEASE_CONFIG_CHANGE);
		} else
			CMGD_EVENT_ADD(peer, CMGD_Stop);

		/* Skip peer-group mechanics for regular peers. */
		return 0;
	}

	/*
	 * Remove flag and configuration from all peer-group members, unless
	 * they are explicitely overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->flags_override, PEER_FLAG_LOCAL_AS))
			continue;

		/* Remove flag and configuration on peer-group member. */
		UNSET_FLAG(member->flags, PEER_FLAG_LOCAL_AS);
		UNSET_FLAG(member->flags, PEER_FLAG_LOCAL_AS_NO_PREPEND);
		UNSET_FLAG(member->flags, PEER_FLAG_LOCAL_AS_REPLACE_AS);
		member->change_local_as = 0;

		/* Send notification or stop peer depending on state. */
		if (CMGD_IS_VALID_STATE_FOR_NOTIF(member->status)) {
			member->last_reset = PEER_DOWN_LOCAL_AS_CHANGE;
			cmgd_notify_send(member, CMGD_NOTIFY_CEASE,
					CMGD_NOTIFY_CEASE_CONFIG_CHANGE);
		} else
			cmgd_session_reset(member);
	}

	return 0;
}

/* Set password for authenticating with the peer. */
int peer_password_set(struct peer *peer, const char *password)
{
	struct peer *member;
	struct listnode *node, *nnode;
	int len = password ? strlen(password) : 0;
	int ret = CMGD_SUCCESS;

	if ((len < PEER_PASSWORD_MINLEN) || (len > PEER_PASSWORD_MAXLEN))
		return CMGD_ERR_INVALID_VALUE;

	/* Set flag and configuration on peer. */
	peer_flag_set(peer, PEER_FLAG_PASSWORD);
	if (peer->password && strcmp(peer->password, password) == 0)
		return 0;
	XFREE(MTYPE_PEER_PASSWORD, peer->password);
	peer->password = XSTRDUP(MTYPE_PEER_PASSWORD, password);

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		/* Send notification or reset peer depending on state. */
		if (CMGD_IS_VALID_STATE_FOR_NOTIF(peer->status))
			cmgd_notify_send(peer, CMGD_NOTIFY_CEASE,
					CMGD_NOTIFY_CEASE_CONFIG_CHANGE);
		else
			cmgd_session_reset(peer);

		/*
		 * Attempt to install password on socket and skip peer-group
		 * mechanics.
		 */
		if (CMGD_PEER_SU_UNSPEC(peer))
			return CMGD_SUCCESS;
		return (cmgd_md5_set(peer) >= 0) ? CMGD_SUCCESS
						: CMGD_ERR_TCPSIG_FAILED;
	}

	/*
	 * Set flag and configuration on all peer-group members, unless they are
	 * explicitely overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->flags_override, PEER_FLAG_PASSWORD))
			continue;

		/* Skip peers with the same password. */
		if (member->password && strcmp(member->password, password) == 0)
			continue;

		/* Set flag and configuration on peer-group member. */
		SET_FLAG(member->flags, PEER_FLAG_PASSWORD);
		if (member->password)
			XFREE(MTYPE_PEER_PASSWORD, member->password);
		member->password = XSTRDUP(MTYPE_PEER_PASSWORD, password);

		/* Send notification or reset peer depending on state. */
		if (CMGD_IS_VALID_STATE_FOR_NOTIF(member->status))
			cmgd_notify_send(member, CMGD_NOTIFY_CEASE,
					CMGD_NOTIFY_CEASE_CONFIG_CHANGE);
		else
			cmgd_session_reset(member);

		/* Attempt to install password on socket. */
		if (!CMGD_PEER_SU_UNSPEC(member) && cmgd_md5_set(member) < 0)
			ret = CMGD_ERR_TCPSIG_FAILED;
	}

	/* Set flag and configuration on all peer-group listen ranges */
	struct listnode *ln;
	struct prefix *lr;

	for (ALL_LIST_ELEMENTS_RO(peer->group->listen_range[AFI_IP], ln, lr))
		cmgd_md5_set_prefix(peer->cmgd, lr, password);
	for (ALL_LIST_ELEMENTS_RO(peer->group->listen_range[AFI_IP6], ln, lr))
		cmgd_md5_set_prefix(peer->cmgd, lr, password);

	return ret;
}

int peer_password_unset(struct peer *peer)
{
	struct peer *member;
	struct listnode *node, *nnode;

	if (!CHECK_FLAG(peer->flags, PEER_FLAG_PASSWORD))
		return 0;

	/* Inherit configuration from peer-group if peer is member. */
	if (peer_group_active(peer)) {
		peer_flag_inherit(peer, PEER_FLAG_PASSWORD);
		PEER_STR_ATTR_INHERIT(peer, peer->group, password,
				      MTYPE_PEER_PASSWORD);
	} else {
		/* Otherwise remove flag and configuration from peer. */
		peer_flag_unset(peer, PEER_FLAG_PASSWORD);
		XFREE(MTYPE_PEER_PASSWORD, peer->password);
	}

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		/* Send notification or reset peer depending on state. */
		if (CMGD_IS_VALID_STATE_FOR_NOTIF(peer->status))
			cmgd_notify_send(peer, CMGD_NOTIFY_CEASE,
					CMGD_NOTIFY_CEASE_CONFIG_CHANGE);
		else
			cmgd_session_reset(peer);

		/* Attempt to uninstall password on socket. */
		if (!CMGD_PEER_SU_UNSPEC(peer))
			cmgd_md5_unset(peer);
		/* Skip peer-group mechanics for regular peers. */
		return 0;
	}

	/*
	 * Remove flag and configuration from all peer-group members, unless
	 * they are explicitely overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->flags_override, PEER_FLAG_PASSWORD))
			continue;

		/* Remove flag and configuration on peer-group member. */
		UNSET_FLAG(member->flags, PEER_FLAG_PASSWORD);
		XFREE(MTYPE_PEER_PASSWORD, member->password);

		/* Send notification or reset peer depending on state. */
		if (CMGD_IS_VALID_STATE_FOR_NOTIF(member->status))
			cmgd_notify_send(member, CMGD_NOTIFY_CEASE,
					CMGD_NOTIFY_CEASE_CONFIG_CHANGE);
		else
			cmgd_session_reset(member);

		/* Attempt to uninstall password on socket. */
		if (!CMGD_PEER_SU_UNSPEC(member))
			cmgd_md5_unset(member);
	}

	/* Set flag and configuration on all peer-group listen ranges */
	struct listnode *ln;
	struct prefix *lr;

	for (ALL_LIST_ELEMENTS_RO(peer->group->listen_range[AFI_IP], ln, lr))
		cmgd_md5_unset_prefix(peer->cmgd, lr);
	for (ALL_LIST_ELEMENTS_RO(peer->group->listen_range[AFI_IP6], ln, lr))
		cmgd_md5_unset_prefix(peer->cmgd, lr);

	return 0;
}


/* Set distribute list to the peer. */
int peer_distribute_set(struct peer *peer, afi_t afi, safi_t safi, int direct,
			const char *name)
{
	struct peer *member;
	struct cmgd_filter *filter;
	struct listnode *node, *nnode;

	if (direct != FILTER_IN && direct != FILTER_OUT)
		return CMGD_ERR_INVALID_VALUE;

	/* Set configuration on peer. */
	filter = &peer->filter[afi][safi];
	if (filter->plist[direct].name)
		return CMGD_ERR_PEER_FILTER_CONFLICT;
	if (filter->dlist[direct].name)
		XFREE(MTYPE_CMGD_FILTER_NAME, filter->dlist[direct].name);
	filter->dlist[direct].name = XSTRDUP(MTYPE_CMGD_FILTER_NAME, name);
	filter->dlist[direct].alist = access_list_lookup(afi, name);

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		/* Set override-flag and process peer route updates. */
		SET_FLAG(peer->filter_override[afi][safi][direct],
			 PEER_FT_DISTRIBUTE_LIST);
		peer_on_policy_change(peer, afi, safi,
				      (direct == FILTER_OUT) ? 1 : 0);

		/* Skip peer-group mechanics for regular peers. */
		return 0;
	}

	/*
	 * Set configuration on all peer-group members, un less they are
	 * explicitely overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->filter_override[afi][safi][direct],
			       PEER_FT_DISTRIBUTE_LIST))
			continue;

		/* Set configuration on peer-group member. */
		filter = &member->filter[afi][safi];
		if (filter->dlist[direct].name)
			XFREE(MTYPE_CMGD_FILTER_NAME,
			      filter->dlist[direct].name);
		filter->dlist[direct].name =
			XSTRDUP(MTYPE_CMGD_FILTER_NAME, name);
		filter->dlist[direct].alist = access_list_lookup(afi, name);

		/* Process peer route updates. */
		peer_on_policy_change(member, afi, safi,
				      (direct == FILTER_OUT) ? 1 : 0);
	}

	return 0;
}

int peer_distribute_unset(struct peer *peer, afi_t afi, safi_t safi, int direct)
{
	struct peer *member;
	struct cmgd_filter *filter;
	struct listnode *node, *nnode;

	if (direct != FILTER_IN && direct != FILTER_OUT)
		return CMGD_ERR_INVALID_VALUE;

	/* Unset override-flag unconditionally. */
	UNSET_FLAG(peer->filter_override[afi][safi][direct],
		   PEER_FT_DISTRIBUTE_LIST);

	/* Inherit configuration from peer-group if peer is member. */
	if (peer_group_active(peer)) {
		PEER_STR_ATTR_INHERIT(peer, peer->group,
				      filter[afi][safi].dlist[direct].name,
				      MTYPE_CMGD_FILTER_NAME);
		PEER_ATTR_INHERIT(peer, peer->group,
				  filter[afi][safi].dlist[direct].alist);
	} else {
		/* Otherwise remove configuration from peer. */
		filter = &peer->filter[afi][safi];
		if (filter->dlist[direct].name)
			XFREE(MTYPE_CMGD_FILTER_NAME,
			      filter->dlist[direct].name);
		filter->dlist[direct].name = NULL;
		filter->dlist[direct].alist = NULL;
	}

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		/* Process peer route updates. */
		peer_on_policy_change(peer, afi, safi,
				      (direct == FILTER_OUT) ? 1 : 0);

		/* Skip peer-group mechanics for regular peers. */
		return 0;
	}

	/*
	 * Remove configuration on all peer-group members, unless they are
	 * explicitely overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->filter_override[afi][safi][direct],
			       PEER_FT_DISTRIBUTE_LIST))
			continue;

		/* Remove configuration on peer-group member. */
		filter = &member->filter[afi][safi];
		if (filter->dlist[direct].name)
			XFREE(MTYPE_CMGD_FILTER_NAME,
			      filter->dlist[direct].name);
		filter->dlist[direct].name = NULL;
		filter->dlist[direct].alist = NULL;

		/* Process peer route updates. */
		peer_on_policy_change(member, afi, safi,
				      (direct == FILTER_OUT) ? 1 : 0);
	}

	return 0;
}

/* Update distribute list. */
static void peer_distribute_update(struct access_list *access)
{
	afi_t afi;
	safi_t safi;
	int direct;
	struct listnode *mnode, *mnnode;
	struct listnode *node, *nnode;
	struct cmgd *cmgd;
	struct peer *peer;
	struct peer_group *group;
	struct cmgd_filter *filter;

	for (ALL_LIST_ELEMENTS(cm->cmgd, mnode, mnnode, cmgd)) {
		if (access->name)
			update_group_policy_update(cmgd, CMGD_POLICY_FILTER_LIST,
						   access->name, 0, 0);
		for (ALL_LIST_ELEMENTS(cmgd->peer, node, nnode, peer)) {
			FOREACH_AFI_SAFI (afi, safi) {
				filter = &peer->filter[afi][safi];

				for (direct = FILTER_IN; direct < FILTER_MAX;
				     direct++) {
					if (filter->dlist[direct].name)
						filter->dlist[direct]
							.alist = access_list_lookup(
							afi,
							filter->dlist[direct]
								.name);
					else
						filter->dlist[direct].alist =
							NULL;
				}
			}
		}
		for (ALL_LIST_ELEMENTS(cmgd->group, node, nnode, group)) {
			FOREACH_AFI_SAFI (afi, safi) {
				filter = &group->conf->filter[afi][safi];

				for (direct = FILTER_IN; direct < FILTER_MAX;
				     direct++) {
					if (filter->dlist[direct].name)
						filter->dlist[direct]
							.alist = access_list_lookup(
							afi,
							filter->dlist[direct]
								.name);
					else
						filter->dlist[direct].alist =
							NULL;
				}
			}
		}
#ifdef ENABLE_CMGD_VNC
		vnc_prefix_list_update(cmgd);
#endif
	}
}

/* Set prefix list to the peer. */
int peer_prefix_list_set(struct peer *peer, afi_t afi, safi_t safi, int direct,
			 const char *name)
{
	struct peer *member;
	struct cmgd_filter *filter;
	struct listnode *node, *nnode;

	if (direct != FILTER_IN && direct != FILTER_OUT)
		return CMGD_ERR_INVALID_VALUE;

	/* Set configuration on peer. */
	filter = &peer->filter[afi][safi];
	if (filter->dlist[direct].name)
		return CMGD_ERR_PEER_FILTER_CONFLICT;
	if (filter->plist[direct].name)
		XFREE(MTYPE_CMGD_FILTER_NAME, filter->plist[direct].name);
	filter->plist[direct].name = XSTRDUP(MTYPE_CMGD_FILTER_NAME, name);
	filter->plist[direct].plist = prefix_list_lookup(afi, name);

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		/* Set override-flag and process peer route updates. */
		SET_FLAG(peer->filter_override[afi][safi][direct],
			 PEER_FT_PREFIX_LIST);
		peer_on_policy_change(peer, afi, safi,
				      (direct == FILTER_OUT) ? 1 : 0);

		/* Skip peer-group mechanics for regular peers. */
		return 0;
	}

	/*
	 * Set configuration on all peer-group members, unless they are
	 * explicitely overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->filter_override[afi][safi][direct],
			       PEER_FT_PREFIX_LIST))
			continue;

		/* Set configuration on peer-group member. */
		filter = &member->filter[afi][safi];
		if (filter->plist[direct].name)
			XFREE(MTYPE_CMGD_FILTER_NAME,
			      filter->plist[direct].name);
		filter->plist[direct].name =
			XSTRDUP(MTYPE_CMGD_FILTER_NAME, name);
		filter->plist[direct].plist = prefix_list_lookup(afi, name);

		/* Process peer route updates. */
		peer_on_policy_change(member, afi, safi,
				      (direct == FILTER_OUT) ? 1 : 0);
	}

	return 0;
}

int peer_prefix_list_unset(struct peer *peer, afi_t afi, safi_t safi,
			   int direct)
{
	struct peer *member;
	struct cmgd_filter *filter;
	struct listnode *node, *nnode;

	if (direct != FILTER_IN && direct != FILTER_OUT)
		return CMGD_ERR_INVALID_VALUE;

	/* Unset override-flag unconditionally. */
	UNSET_FLAG(peer->filter_override[afi][safi][direct],
		   PEER_FT_PREFIX_LIST);

	/* Inherit configuration from peer-group if peer is member. */
	if (peer_group_active(peer)) {
		PEER_STR_ATTR_INHERIT(peer, peer->group,
				      filter[afi][safi].plist[direct].name,
				      MTYPE_CMGD_FILTER_NAME);
		PEER_ATTR_INHERIT(peer, peer->group,
				  filter[afi][safi].plist[direct].plist);
	} else {
		/* Otherwise remove configuration from peer. */
		filter = &peer->filter[afi][safi];
		if (filter->plist[direct].name)
			XFREE(MTYPE_CMGD_FILTER_NAME,
			      filter->plist[direct].name);
		filter->plist[direct].name = NULL;
		filter->plist[direct].plist = NULL;
	}

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		/* Process peer route updates. */
		peer_on_policy_change(peer, afi, safi,
				      (direct == FILTER_OUT) ? 1 : 0);

		/* Skip peer-group mechanics for regular peers. */
		return 0;
	}

	/*
	 * Remove configuration on all peer-group members, unless they are
	 * explicitely overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->filter_override[afi][safi][direct],
			       PEER_FT_PREFIX_LIST))
			continue;

		/* Remove configuration on peer-group member. */
		filter = &member->filter[afi][safi];
		if (filter->plist[direct].name)
			XFREE(MTYPE_CMGD_FILTER_NAME,
			      filter->plist[direct].name);
		filter->plist[direct].name = NULL;
		filter->plist[direct].plist = NULL;

		/* Process peer route updates. */
		peer_on_policy_change(member, afi, safi,
				      (direct == FILTER_OUT) ? 1 : 0);
	}

	return 0;
}

/* Update prefix-list list. */
static void peer_prefix_list_update(struct prefix_list *plist)
{
	struct listnode *mnode, *mnnode;
	struct listnode *node, *nnode;
	struct cmgd *cmgd;
	struct peer *peer;
	struct peer_group *group;
	struct cmgd_filter *filter;
	afi_t afi;
	safi_t safi;
	int direct;

	for (ALL_LIST_ELEMENTS(cm->cmgd, mnode, mnnode, cmgd)) {

		/*
		 * Update the prefix-list on update groups.
		 */
		update_group_policy_update(
			cmgd, CMGD_POLICY_PREFIX_LIST,
			plist ? prefix_list_name(plist) : NULL, 0, 0);

		for (ALL_LIST_ELEMENTS(cmgd->peer, node, nnode, peer)) {
			FOREACH_AFI_SAFI (afi, safi) {
				filter = &peer->filter[afi][safi];

				for (direct = FILTER_IN; direct < FILTER_MAX;
				     direct++) {
					if (filter->plist[direct].name)
						filter->plist[direct]
							.plist = prefix_list_lookup(
							afi,
							filter->plist[direct]
								.name);
					else
						filter->plist[direct].plist =
							NULL;
				}
			}
		}
		for (ALL_LIST_ELEMENTS(cmgd->group, node, nnode, group)) {
			FOREACH_AFI_SAFI (afi, safi) {
				filter = &group->conf->filter[afi][safi];

				for (direct = FILTER_IN; direct < FILTER_MAX;
				     direct++) {
					if (filter->plist[direct].name)
						filter->plist[direct]
							.plist = prefix_list_lookup(
							afi,
							filter->plist[direct]
								.name);
					else
						filter->plist[direct].plist =
							NULL;
				}
			}
		}
	}
}

int peer_aslist_set(struct peer *peer, afi_t afi, safi_t safi, int direct,
		    const char *name)
{
	struct peer *member;
	struct cmgd_filter *filter;
	struct listnode *node, *nnode;

	if (direct != FILTER_IN && direct != FILTER_OUT)
		return CMGD_ERR_INVALID_VALUE;

	/* Set configuration on peer. */
	filter = &peer->filter[afi][safi];
	if (filter->aslist[direct].name)
		XFREE(MTYPE_CMGD_FILTER_NAME, filter->aslist[direct].name);
	filter->aslist[direct].name = XSTRDUP(MTYPE_CMGD_FILTER_NAME, name);
	filter->aslist[direct].aslist = as_list_lookup(name);

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		/* Set override-flag and process peer route updates. */
		SET_FLAG(peer->filter_override[afi][safi][direct],
			 PEER_FT_FILTER_LIST);
		peer_on_policy_change(peer, afi, safi,
				      (direct == FILTER_OUT) ? 1 : 0);

		/* Skip peer-group mechanics for regular peers. */
		return 0;
	}

	/*
	 * Set configuration on all peer-group members, unless they are
	 * explicitely overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->filter_override[afi][safi][direct],
			       PEER_FT_FILTER_LIST))
			continue;

		/* Set configuration on peer-group member. */
		filter = &member->filter[afi][safi];
		if (filter->aslist[direct].name)
			XFREE(MTYPE_CMGD_FILTER_NAME,
			      filter->aslist[direct].name);
		filter->aslist[direct].name =
			XSTRDUP(MTYPE_CMGD_FILTER_NAME, name);
		filter->aslist[direct].aslist = as_list_lookup(name);

		/* Process peer route updates. */
		peer_on_policy_change(member, afi, safi,
				      (direct == FILTER_OUT) ? 1 : 0);
	}

	return 0;
}

int peer_aslist_unset(struct peer *peer, afi_t afi, safi_t safi, int direct)
{
	struct peer *member;
	struct cmgd_filter *filter;
	struct listnode *node, *nnode;

	if (direct != FILTER_IN && direct != FILTER_OUT)
		return CMGD_ERR_INVALID_VALUE;

	/* Unset override-flag unconditionally. */
	UNSET_FLAG(peer->filter_override[afi][safi][direct],
		   PEER_FT_FILTER_LIST);

	/* Inherit configuration from peer-group if peer is member. */
	if (peer_group_active(peer)) {
		PEER_STR_ATTR_INHERIT(peer, peer->group,
				      filter[afi][safi].aslist[direct].name,
				      MTYPE_CMGD_FILTER_NAME);
		PEER_ATTR_INHERIT(peer, peer->group,
				  filter[afi][safi].aslist[direct].aslist);
	} else {
		/* Otherwise remove configuration from peer. */
		filter = &peer->filter[afi][safi];
		if (filter->aslist[direct].name)
			XFREE(MTYPE_CMGD_FILTER_NAME,
			      filter->aslist[direct].name);
		filter->aslist[direct].name = NULL;
		filter->aslist[direct].aslist = NULL;
	}

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		/* Process peer route updates. */
		peer_on_policy_change(peer, afi, safi,
				      (direct == FILTER_OUT) ? 1 : 0);

		/* Skip peer-group mechanics for regular peers. */
		return 0;
	}

	/*
	 * Remove configuration on all peer-group members, unless they are
	 * explicitely overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->filter_override[afi][safi][direct],
			       PEER_FT_FILTER_LIST))
			continue;

		/* Remove configuration on peer-group member. */
		filter = &member->filter[afi][safi];
		if (filter->aslist[direct].name)
			XFREE(MTYPE_CMGD_FILTER_NAME,
			      filter->aslist[direct].name);
		filter->aslist[direct].name = NULL;
		filter->aslist[direct].aslist = NULL;

		/* Process peer route updates. */
		peer_on_policy_change(member, afi, safi,
				      (direct == FILTER_OUT) ? 1 : 0);
	}

	return 0;
}

static void peer_aslist_update(const char *aslist_name)
{
	afi_t afi;
	safi_t safi;
	int direct;
	struct listnode *mnode, *mnnode;
	struct listnode *node, *nnode;
	struct cmgd *cmgd;
	struct peer *peer;
	struct peer_group *group;
	struct cmgd_filter *filter;

	for (ALL_LIST_ELEMENTS(cm->cmgd, mnode, mnnode, cmgd)) {
		update_group_policy_update(cmgd, CMGD_POLICY_FILTER_LIST,
					   aslist_name, 0, 0);

		for (ALL_LIST_ELEMENTS(cmgd->peer, node, nnode, peer)) {
			FOREACH_AFI_SAFI (afi, safi) {
				filter = &peer->filter[afi][safi];

				for (direct = FILTER_IN; direct < FILTER_MAX;
				     direct++) {
					if (filter->aslist[direct].name)
						filter->aslist[direct]
							.aslist = as_list_lookup(
							filter->aslist[direct]
								.name);
					else
						filter->aslist[direct].aslist =
							NULL;
				}
			}
		}
		for (ALL_LIST_ELEMENTS(cmgd->group, node, nnode, group)) {
			FOREACH_AFI_SAFI (afi, safi) {
				filter = &group->conf->filter[afi][safi];

				for (direct = FILTER_IN; direct < FILTER_MAX;
				     direct++) {
					if (filter->aslist[direct].name)
						filter->aslist[direct]
							.aslist = as_list_lookup(
							filter->aslist[direct]
								.name);
					else
						filter->aslist[direct].aslist =
							NULL;
				}
			}
		}
	}
}

static void peer_aslist_add(char *aslist_name)
{
	peer_aslist_update(aslist_name);
	route_map_notify_dependencies(aslist_name, RMAP_EVENT_ASLIST_ADDED);
}

static void peer_aslist_del(const char *aslist_name)
{
	peer_aslist_update(aslist_name);
	route_map_notify_dependencies(aslist_name, RMAP_EVENT_ASLIST_DELETED);
}


int peer_route_map_set(struct peer *peer, afi_t afi, safi_t safi, int direct,
		       const char *name, struct route_map *route_map)
{
	struct peer *member;
	struct cmgd_filter *filter;
	struct listnode *node, *nnode;

	if (direct != RMAP_IN && direct != RMAP_OUT)
		return CMGD_ERR_INVALID_VALUE;

	/* Set configuration on peer. */
	filter = &peer->filter[afi][safi];
	if (filter->map[direct].name) {
		/* If the neighbor is configured with the same route-map
		 * again then, ignore the duplicate configuration.
		 */
		if (strcmp(filter->map[direct].name, name) == 0)
			return 0;

		XFREE(MTYPE_CMGD_FILTER_NAME, filter->map[direct].name);
	}
	route_map_counter_decrement(filter->map[direct].map);
	filter->map[direct].name = XSTRDUP(MTYPE_CMGD_FILTER_NAME, name);
	filter->map[direct].map = route_map;
	route_map_counter_increment(route_map);

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		/* Set override-flag and process peer route updates. */
		SET_FLAG(peer->filter_override[afi][safi][direct],
			 PEER_FT_ROUTE_MAP);
		peer_on_policy_change(peer, afi, safi,
				      (direct == RMAP_OUT) ? 1 : 0);

		/* Skip peer-group mechanics for regular peers. */
		return 0;
	}

	/*
	 * Set configuration on all peer-group members, unless they are
	 * explicitely overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->filter_override[afi][safi][direct],
			       PEER_FT_ROUTE_MAP))
			continue;

		/* Set configuration on peer-group member. */
		filter = &member->filter[afi][safi];
		if (filter->map[direct].name)
			XFREE(MTYPE_CMGD_FILTER_NAME, filter->map[direct].name);
		route_map_counter_decrement(filter->map[direct].map);
		filter->map[direct].name = XSTRDUP(MTYPE_CMGD_FILTER_NAME, name);
		filter->map[direct].map = route_map;
		route_map_counter_increment(route_map);

		/* Process peer route updates. */
		peer_on_policy_change(member, afi, safi,
				      (direct == RMAP_OUT) ? 1 : 0);
	}
	return 0;
}

/* Unset route-map from the peer. */
int peer_route_map_unset(struct peer *peer, afi_t afi, safi_t safi, int direct)
{
	struct peer *member;
	struct cmgd_filter *filter;
	struct listnode *node, *nnode;

	if (direct != RMAP_IN && direct != RMAP_OUT)
		return CMGD_ERR_INVALID_VALUE;

	/* Unset override-flag unconditionally. */
	UNSET_FLAG(peer->filter_override[afi][safi][direct], PEER_FT_ROUTE_MAP);

	/* Inherit configuration from peer-group if peer is member. */
	if (peer_group_active(peer)) {
		PEER_STR_ATTR_INHERIT(peer, peer->group,
				      filter[afi][safi].map[direct].name,
				      MTYPE_CMGD_FILTER_NAME);
		PEER_ATTR_INHERIT(peer, peer->group,
				  filter[afi][safi].map[direct].map);
	} else {
		/* Otherwise remove configuration from peer. */
		filter = &peer->filter[afi][safi];
		if (filter->map[direct].name)
			XFREE(MTYPE_CMGD_FILTER_NAME, filter->map[direct].name);
		route_map_counter_decrement(filter->map[direct].map);
		filter->map[direct].name = NULL;
		filter->map[direct].map = NULL;
	}

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		/* Process peer route updates. */
		peer_on_policy_change(peer, afi, safi,
				      (direct == RMAP_OUT) ? 1 : 0);

		/* Skip peer-group mechanics for regular peers. */
		return 0;
	}

	/*
	 * Remove configuration on all peer-group members, unless they are
	 * explicitely overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->filter_override[afi][safi][direct],
			       PEER_FT_ROUTE_MAP))
			continue;

		/* Remove configuration on peer-group member. */
		filter = &member->filter[afi][safi];
		if (filter->map[direct].name)
			XFREE(MTYPE_CMGD_FILTER_NAME, filter->map[direct].name);
		route_map_counter_decrement(filter->map[direct].map);
		filter->map[direct].name = NULL;
		filter->map[direct].map = NULL;

		/* Process peer route updates. */
		peer_on_policy_change(member, afi, safi,
				      (direct == RMAP_OUT) ? 1 : 0);
	}

	return 0;
}

/* Set unsuppress-map to the peer. */
int peer_unsuppress_map_set(struct peer *peer, afi_t afi, safi_t safi,
			    const char *name, struct route_map *route_map)
{
	struct peer *member;
	struct cmgd_filter *filter;
	struct listnode *node, *nnode;

	/* Set configuration on peer. */
	filter = &peer->filter[afi][safi];
	if (filter->usmap.name)
		XFREE(MTYPE_CMGD_FILTER_NAME, filter->usmap.name);
	route_map_counter_decrement(filter->usmap.map);
	filter->usmap.name = XSTRDUP(MTYPE_CMGD_FILTER_NAME, name);
	filter->usmap.map = route_map;
	route_map_counter_increment(route_map);

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		/* Set override-flag and process peer route updates. */
		SET_FLAG(peer->filter_override[afi][safi][0],
			 PEER_FT_UNSUPPRESS_MAP);
		peer_on_policy_change(peer, afi, safi, 1);

		/* Skip peer-group mechanics for regular peers. */
		return 0;
	}

	/*
	 * Set configuration on all peer-group members, unless they are
	 * explicitely overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->filter_override[afi][safi][0],
			       PEER_FT_UNSUPPRESS_MAP))
			continue;

		/* Set configuration on peer-group member. */
		filter = &member->filter[afi][safi];
		if (filter->usmap.name)
			XFREE(MTYPE_CMGD_FILTER_NAME, filter->usmap.name);
		route_map_counter_decrement(filter->usmap.map);
		filter->usmap.name = XSTRDUP(MTYPE_CMGD_FILTER_NAME, name);
		filter->usmap.map = route_map;
		route_map_counter_increment(route_map);

		/* Process peer route updates. */
		peer_on_policy_change(member, afi, safi, 1);
	}

	return 0;
}

/* Unset route-map from the peer. */
int peer_unsuppress_map_unset(struct peer *peer, afi_t afi, safi_t safi)
{
	struct peer *member;
	struct cmgd_filter *filter;
	struct listnode *node, *nnode;

	/* Unset override-flag unconditionally. */
	UNSET_FLAG(peer->filter_override[afi][safi][0], PEER_FT_UNSUPPRESS_MAP);

	/* Inherit configuration from peer-group if peer is member. */
	if (peer_group_active(peer)) {
		PEER_STR_ATTR_INHERIT(peer, peer->group,
				      filter[afi][safi].usmap.name,
				      MTYPE_CMGD_FILTER_NAME);
		PEER_ATTR_INHERIT(peer, peer->group,
				  filter[afi][safi].usmap.map);
	} else {
		/* Otherwise remove configuration from peer. */
		filter = &peer->filter[afi][safi];
		if (filter->usmap.name)
			XFREE(MTYPE_CMGD_FILTER_NAME, filter->usmap.name);
		route_map_counter_decrement(filter->usmap.map);
		filter->usmap.name = NULL;
		filter->usmap.map = NULL;
	}

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		/* Process peer route updates. */
		peer_on_policy_change(peer, afi, safi, 1);

		/* Skip peer-group mechanics for regular peers. */
		return 0;
	}

	/*
	 * Remove configuration on all peer-group members, unless they are
	 * explicitely overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->filter_override[afi][safi][0],
			       PEER_FT_UNSUPPRESS_MAP))
			continue;

		/* Remove configuration on peer-group member. */
		filter = &member->filter[afi][safi];
		if (filter->usmap.name)
			XFREE(MTYPE_CMGD_FILTER_NAME, filter->usmap.name);
		route_map_counter_decrement(filter->usmap.map);
		filter->usmap.name = NULL;
		filter->usmap.map = NULL;

		/* Process peer route updates. */
		peer_on_policy_change(member, afi, safi, 1);
	}

	return 0;
}

static void peer_advertise_map_filter_update(struct peer *peer, afi_t afi,
					     safi_t safi, const char *amap_name,
					     struct route_map *amap,
					     const char *cmap_name,
					     struct route_map *cmap,
					     bool condition, bool set)
{
	struct cmgd_filter *filter;
	bool filter_exists = false;

	filter = &peer->filter[afi][safi];

	/* advertise-map is already configured. */
	if (filter->advmap.aname) {
		filter_exists = true;
		XFREE(MTYPE_CMGD_FILTER_NAME, filter->advmap.aname);
		XFREE(MTYPE_CMGD_FILTER_NAME, filter->advmap.cname);
	}

	route_map_counter_decrement(filter->advmap.amap);

	/* Removed advertise-map configuration */
	if (!set) {
		memset(filter, 0, sizeof(struct cmgd_filter));

		/* decrement condition_filter_count delete timer if
		 * this is the last advertise-map to be removed.
		 */
		if (filter_exists)
			cmgd_conditional_adv_disable(peer, afi, safi);

		return;
	}

	/* Update filter data with newly configured values. */
	filter->advmap.aname = XSTRDUP(MTYPE_CMGD_FILTER_NAME, amap_name);
	filter->advmap.cname = XSTRDUP(MTYPE_CMGD_FILTER_NAME, cmap_name);
	filter->advmap.amap = amap;
	filter->advmap.cmap = cmap;
	filter->advmap.condition = condition;
	route_map_counter_increment(filter->advmap.amap);
	peer->advmap_config_change[afi][safi] = true;

	/* Increment condition_filter_count and/or create timer. */
	if (!filter_exists) {
		filter->advmap.update_type = ADVERTISE;
		cmgd_conditional_adv_enable(peer, afi, safi);
	}
}

/* Set advertise-map to the peer but do not process peer route updates here.  *
 * Hold filter changes until the conditional routes polling thread is called  *
 * AS we need to advertise/withdraw prefixes (in advertise-map) based on the  *
 * condition (exist-map/non-exist-map) and routes(specified in condition-map) *
 * in CMGD table. So do not call peer_on_policy_change() here, only create     *
 * polling timer thread, update filters and increment condition_filter_count.
 */
int peer_advertise_map_set(struct peer *peer, afi_t afi, safi_t safi,
			   const char *advertise_name,
			   struct route_map *advertise_map,
			   const char *condition_name,
			   struct route_map *condition_map, bool condition)
{
	struct peer *member;
	struct listnode *node, *nnode;

	/* Set configuration on peer. */
	peer_advertise_map_filter_update(peer, afi, safi, advertise_name,
					 advertise_map, condition_name,
					 condition_map, condition, true);

	/* Check if handling a regular peer & Skip peer-group mechanics. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		/* Set override-flag and process peer route updates. */
		SET_FLAG(peer->filter_override[afi][safi][RMAP_OUT],
			 PEER_FT_ADVERTISE_MAP);
		return 0;
	}

	/*
	 * Set configuration on all peer-group members, unless they are
	 * explicitely overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->filter_override[afi][safi][RMAP_OUT],
			       PEER_FT_ADVERTISE_MAP))
			continue;

		/* Set configuration on peer-group member. */
		peer_advertise_map_filter_update(
			member, afi, safi, advertise_name, advertise_map,
			condition_name, condition_map, condition, true);
	}

	return 0;
}

/* Unset advertise-map from the peer. */
int peer_advertise_map_unset(struct peer *peer, afi_t afi, safi_t safi,
			     const char *advertise_name,
			     struct route_map *advertise_map,
			     const char *condition_name,
			     struct route_map *condition_map, bool condition)
{
	struct peer *member;
	struct listnode *node, *nnode;

	/* advertise-map is not configured */
	if (!peer->filter[afi][safi].advmap.aname)
		return 0;

	/* Unset override-flag unconditionally. */
	UNSET_FLAG(peer->filter_override[afi][safi][RMAP_OUT],
		   PEER_FT_ADVERTISE_MAP);

	/* Inherit configuration from peer-group if peer is member. */
	if (peer_group_active(peer)) {
		PEER_STR_ATTR_INHERIT(peer, peer->group,
				      filter[afi][safi].advmap.aname,
				      MTYPE_CMGD_FILTER_NAME);
		PEER_ATTR_INHERIT(peer, peer->group,
				  filter[afi][safi].advmap.amap);
	} else
		peer_advertise_map_filter_update(
			peer, afi, safi, advertise_name, advertise_map,
			condition_name, condition_map, condition, false);

	/* Check if handling a regular peer and skip peer-group mechanics. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		/* Process peer route updates. */
		if (CMGD_DEBUG(update, UPDATE_OUT))
			zlog_debug("%s: Send normal update to %s for %s",
				   __func__, peer->host,
				   get_afi_safi_str(afi, safi, false));

		peer_on_policy_change(peer, afi, safi, 1);
		return 0;
	}

	/*
	 * Remove configuration on all peer-group members, unless they are
	 * explicitely overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->filter_override[afi][safi][RMAP_OUT],
			       PEER_FT_ADVERTISE_MAP))
			continue;
		/* Remove configuration on peer-group member. */
		peer_advertise_map_filter_update(
			member, afi, safi, advertise_name, advertise_map,
			condition_name, condition_map, condition, false);

		/* Process peer route updates. */
		if (CMGD_DEBUG(update, UPDATE_OUT))
			zlog_debug("%s: Send normal update to %s for %s ",
				   __func__, member->host,
				   get_afi_safi_str(afi, safi, false));

		peer_on_policy_change(member, afi, safi, 1);
	}

	return 0;
}

static bool peer_maximum_prefix_clear_overflow(struct peer *peer)
{
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_PREFIX_OVERFLOW))
		return false;

	UNSET_FLAG(peer->sflags, PEER_STATUS_PREFIX_OVERFLOW);
	if (peer->t_pmax_restart) {
		CMGD_TIMER_OFF(peer->t_pmax_restart);
		if (cmgd_debug_neighbor_events(peer))
			zlog_debug("%s Maximum-prefix restart timer cancelled",
				   peer->host);
	}
	CMGD_EVENT_ADD(peer, CMGD_Start);
	return true;
}

int peer_maximum_prefix_set(struct peer *peer, afi_t afi, safi_t safi,
			    uint32_t max, uint8_t threshold, int warning,
			    uint16_t restart, bool force)
{
	struct peer *member;
	struct listnode *node, *nnode;

	/* Set flags and configuration on peer. */
	peer_af_flag_set(peer, afi, safi, PEER_FLAG_MAX_PREFIX);

	if (force)
		peer_af_flag_set(peer, afi, safi, PEER_FLAG_MAX_PREFIX_FORCE);
	else
		peer_af_flag_unset(peer, afi, safi, PEER_FLAG_MAX_PREFIX_FORCE);

	if (warning)
		peer_af_flag_set(peer, afi, safi, PEER_FLAG_MAX_PREFIX_WARNING);
	else
		peer_af_flag_unset(peer, afi, safi,
				   PEER_FLAG_MAX_PREFIX_WARNING);

	peer->pmax[afi][safi] = max;
	peer->pmax_threshold[afi][safi] = threshold;
	peer->pmax_restart[afi][safi] = restart;

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		/* Re-check if peer violates maximum-prefix. */
		if ((peer->status == Established) && (peer->afc[afi][safi]))
			cmgd_maximum_prefix_overflow(peer, afi, safi, 1);

		/* Skip peer-group mechanics for regular peers. */
		return 0;
	}

	/*
	 * Set flags and configuration on all peer-group members, unless they
	 * are explicitely overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->af_flags_override[afi][safi],
			       PEER_FLAG_MAX_PREFIX))
			continue;

		/* Set flag and configuration on peer-group member. */
		member->pmax[afi][safi] = max;
		member->pmax_threshold[afi][safi] = threshold;
		member->pmax_restart[afi][safi] = restart;

		if (force)
			SET_FLAG(member->af_flags[afi][safi],
				 PEER_FLAG_MAX_PREFIX_FORCE);
		else
			UNSET_FLAG(member->af_flags[afi][safi],
				   PEER_FLAG_MAX_PREFIX_FORCE);

		if (warning)
			SET_FLAG(member->af_flags[afi][safi],
				 PEER_FLAG_MAX_PREFIX_WARNING);
		else
			UNSET_FLAG(member->af_flags[afi][safi],
				   PEER_FLAG_MAX_PREFIX_WARNING);

		/* Re-check if peer violates maximum-prefix. */
		if ((member->status == Established) && (member->afc[afi][safi]))
			cmgd_maximum_prefix_overflow(member, afi, safi, 1);
	}

	return 0;
}

int peer_maximum_prefix_unset(struct peer *peer, afi_t afi, safi_t safi)
{
	/* Inherit configuration from peer-group if peer is member. */
	if (peer_group_active(peer)) {
		peer_af_flag_inherit(peer, afi, safi, PEER_FLAG_MAX_PREFIX);
		peer_af_flag_inherit(peer, afi, safi,
				     PEER_FLAG_MAX_PREFIX_FORCE);
		peer_af_flag_inherit(peer, afi, safi,
				     PEER_FLAG_MAX_PREFIX_WARNING);
		PEER_ATTR_INHERIT(peer, peer->group, pmax[afi][safi]);
		PEER_ATTR_INHERIT(peer, peer->group, pmax_threshold[afi][safi]);
		PEER_ATTR_INHERIT(peer, peer->group, pmax_restart[afi][safi]);

		return 0;
	}

	/* Remove flags and configuration from peer. */
	peer_af_flag_unset(peer, afi, safi, PEER_FLAG_MAX_PREFIX);
	peer_af_flag_unset(peer, afi, safi, PEER_FLAG_MAX_PREFIX_FORCE);
	peer_af_flag_unset(peer, afi, safi, PEER_FLAG_MAX_PREFIX_WARNING);
	peer->pmax[afi][safi] = 0;
	peer->pmax_threshold[afi][safi] = 0;
	peer->pmax_restart[afi][safi] = 0;

	/*
	 * Remove flags and configuration from all peer-group members, unless
	 * they are explicitely overriding peer-group configuration.
	 */
	if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		struct peer *member;
		struct listnode *node;

		for (ALL_LIST_ELEMENTS_RO(peer->group->peer, node, member)) {
			/* Skip peers with overridden configuration. */
			if (CHECK_FLAG(member->af_flags_override[afi][safi],
				       PEER_FLAG_MAX_PREFIX))
				continue;

			/* Remove flag and configuration on peer-group member.
			 */
			UNSET_FLAG(member->af_flags[afi][safi],
				   PEER_FLAG_MAX_PREFIX);
			UNSET_FLAG(member->af_flags[afi][safi],
				   PEER_FLAG_MAX_PREFIX_FORCE);
			UNSET_FLAG(member->af_flags[afi][safi],
				   PEER_FLAG_MAX_PREFIX_WARNING);
			member->pmax[afi][safi] = 0;
			member->pmax_threshold[afi][safi] = 0;
			member->pmax_restart[afi][safi] = 0;

			peer_maximum_prefix_clear_overflow(member);
		}
	} else {
		peer_maximum_prefix_clear_overflow(peer);
	}

	return 0;
}

int is_ecmgd_multihop_configured(struct peer *peer)
{
	struct peer_group *group;
	struct listnode *node, *nnode;
	struct peer *peer1;

	if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		group = peer->group;
		if ((peer_sort(peer) != CMGD_PEER_ICMGD)
		    && (group->conf->ttl != CMGD_DEFAULT_TTL))
			return 1;

		for (ALL_LIST_ELEMENTS(group->peer, node, nnode, peer1)) {
			if ((peer_sort(peer1) != CMGD_PEER_ICMGD)
			    && (peer1->ttl != CMGD_DEFAULT_TTL))
				return 1;
		}
	} else {
		if ((peer_sort(peer) != CMGD_PEER_ICMGD)
		    && (peer->ttl != CMGD_DEFAULT_TTL))
			return 1;
	}
	return 0;
}

/* Set # of hops between us and CMGD peer. */
int peer_ttl_security_hops_set(struct peer *peer, int gtsm_hops)
{
	struct peer_group *group;
	struct peer *gpeer;
	struct listnode *node, *nnode;
	int ret;

	zlog_debug("%s: set gtsm_hops to %d for %s", __func__, gtsm_hops,
		   peer->host);

	/* We cannot configure ttl-security hops when ecmgd-multihop is already
	   set.  For non peer-groups, the check is simple.  For peer-groups,
	   it's
	   slightly messy, because we need to check both the peer-group
	   structure
	   and all peer-group members for any trace of ecmgd-multihop
	   configuration
	   before actually applying the ttl-security rules.  Cisco really made a
	   mess of this configuration parameter, and OpenCMGDD got it right.
	*/

	if ((peer->gtsm_hops == CMGD_GTSM_HOPS_DISABLED)
	    && (peer->sort != CMGD_PEER_ICMGD)) {
		if (is_ecmgd_multihop_configured(peer))
			return CMGD_ERR_NO_ECMGD_MULTIHOP_WITH_TTLHACK;

		if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
			peer->gtsm_hops = gtsm_hops;

			/* Calling ecmgd multihop also resets the session.
			 * On restart, NHT will get setup correctly as will the
			 * min & max ttls on the socket. The return value is
			 * irrelevant.
			 */
			ret = peer_ecmgd_multihop_set(peer, MAXTTL);

			if (ret != 0)
				return ret;
		} else {
			group = peer->group;
			group->conf->gtsm_hops = gtsm_hops;
			for (ALL_LIST_ELEMENTS(group->peer, node, nnode,
					       gpeer)) {
				gpeer->gtsm_hops = group->conf->gtsm_hops;

				/* Calling ecmgd multihop also resets the
				 * session.
				 * On restart, NHT will get setup correctly as
				 * will the
				 * min & max ttls on the socket. The return
				 * value is
				 * irrelevant.
				 */
				peer_ecmgd_multihop_set(gpeer, MAXTTL);
			}
		}
	} else {
		/* Post the first gtsm setup or if its icmgd, maxttl setting
		 * isn't
		 * necessary, just set the minttl.
		 */
		if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
			peer->gtsm_hops = gtsm_hops;

			if (peer->fd >= 0)
				sockopt_minttl(peer->su.sa.sa_family, peer->fd,
					       MAXTTL + 1 - gtsm_hops);
			if ((peer->status < Established) && peer->doppelganger
			    && (peer->doppelganger->fd >= 0))
				sockopt_minttl(peer->su.sa.sa_family,
					       peer->doppelganger->fd,
					       MAXTTL + 1 - gtsm_hops);
		} else {
			group = peer->group;
			group->conf->gtsm_hops = gtsm_hops;
			for (ALL_LIST_ELEMENTS(group->peer, node, nnode,
					       gpeer)) {
				gpeer->gtsm_hops = group->conf->gtsm_hops;

				/* Change setting of existing peer
				 *   established then change value (may break
				 * connectivity)
				 *   not established yet (teardown session and
				 * restart)
				 *   no session then do nothing (will get
				 * handled by next connection)
				 */
				if (gpeer->fd >= 0
				    && gpeer->gtsm_hops
					       != CMGD_GTSM_HOPS_DISABLED)
					sockopt_minttl(
						gpeer->su.sa.sa_family,
						gpeer->fd,
						MAXTTL + 1 - gpeer->gtsm_hops);
				if ((gpeer->status < Established)
				    && gpeer->doppelganger
				    && (gpeer->doppelganger->fd >= 0))
					sockopt_minttl(gpeer->su.sa.sa_family,
						       gpeer->doppelganger->fd,
						       MAXTTL + 1 - gtsm_hops);
			}
		}
	}

	return 0;
}

int peer_ttl_security_hops_unset(struct peer *peer)
{
	struct peer_group *group;
	struct listnode *node, *nnode;
	int ret = 0;

	zlog_debug("%s: set gtsm_hops to zero for %s", __func__, peer->host);

	/* if a peer-group member, then reset to peer-group default rather than
	 * 0 */
	if (peer_group_active(peer))
		peer->gtsm_hops = peer->group->conf->gtsm_hops;
	else
		peer->gtsm_hops = CMGD_GTSM_HOPS_DISABLED;

	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		/* Invoking ecmgd_multihop_set will set the TTL back to the
		 * original
		 * value as well as restting the NHT and such. The session is
		 * reset.
		 */
		if (peer->sort == CMGD_PEER_ECMGD)
			ret = peer_ecmgd_multihop_unset(peer);
		else {
			if (peer->fd >= 0)
				sockopt_minttl(peer->su.sa.sa_family, peer->fd,
					       0);

			if ((peer->status < Established) && peer->doppelganger
			    && (peer->doppelganger->fd >= 0))
				sockopt_minttl(peer->su.sa.sa_family,
					       peer->doppelganger->fd, 0);
		}
	} else {
		group = peer->group;
		for (ALL_LIST_ELEMENTS(group->peer, node, nnode, peer)) {
			peer->gtsm_hops = CMGD_GTSM_HOPS_DISABLED;
			if (peer->sort == CMGD_PEER_ECMGD)
				ret = peer_ecmgd_multihop_unset(peer);
			else {
				if (peer->fd >= 0)
					sockopt_minttl(peer->su.sa.sa_family,
						       peer->fd, 0);

				if ((peer->status < Established)
				    && peer->doppelganger
				    && (peer->doppelganger->fd >= 0))
					sockopt_minttl(peer->su.sa.sa_family,
						       peer->doppelganger->fd,
						       0);
			}
		}
	}

	return ret;
}

/*
 * If peer clear is invoked in a loop for all peers on the CMGD instance,
 * it may end up freeing the doppelganger, and if this was the next node
 * to the current node, we would end up accessing the freed next node.
 * Pass along additional parameter which can be updated if next node
 * is freed; only required when walking the peer list on CMGD instance.
 */
int peer_clear(struct peer *peer, struct listnode **nnode)
{
	if (!CHECK_FLAG(peer->flags, PEER_FLAG_SHUTDOWN)
	    || !CHECK_FLAG(peer->cmgd->flags, CMGD_FLAG_SHUTDOWN)) {
		if (peer_maximum_prefix_clear_overflow(peer))
			return 0;

		peer->v_start = CMGD_INIT_START_TIMER;
		if (CMGD_IS_VALID_STATE_FOR_NOTIF(peer->status))
			cmgd_notify_send(peer, CMGD_NOTIFY_CEASE,
					CMGD_NOTIFY_CEASE_ADMIN_RESET);
		else
			cmgd_session_reset_safe(peer, nnode);
	}
	return 0;
}

int peer_clear_soft(struct peer *peer, afi_t afi, safi_t safi,
		    enum cmgd_clear_type stype)
{
	struct peer_af *paf;

	if (peer->status != Established)
		return 0;

	if (!peer->afc[afi][safi])
		return CMGD_ERR_AF_UNCONFIGURED;

	peer->rtt = sockopt_tcp_rtt(peer->fd);

	if (stype == CMGD_CLEAR_SOFT_OUT || stype == CMGD_CLEAR_SOFT_BOTH) {
		/* Clear the "neighbor x.x.x.x default-originate" flag */
		paf = peer_af_find(peer, afi, safi);
		if (paf && paf->subgroup
		    && CHECK_FLAG(paf->subgroup->sflags,
				  SUBGRP_STATUS_DEFAULT_ORIGINATE))
			UNSET_FLAG(paf->subgroup->sflags,
				   SUBGRP_STATUS_DEFAULT_ORIGINATE);

		cmgd_announce_route(peer, afi, safi);
	}

	if (stype == CMGD_CLEAR_SOFT_IN_ORF_PREFIX) {
		if (CHECK_FLAG(peer->af_cap[afi][safi],
			       PEER_CAP_ORF_PREFIX_SM_ADV)
		    && (CHECK_FLAG(peer->af_cap[afi][safi],
				   PEER_CAP_ORF_PREFIX_RM_RCV)
			|| CHECK_FLAG(peer->af_cap[afi][safi],
				      PEER_CAP_ORF_PREFIX_RM_OLD_RCV))) {
			struct cmgd_filter *filter = &peer->filter[afi][safi];
			uint8_t prefix_type;

			if (CHECK_FLAG(peer->af_cap[afi][safi],
				       PEER_CAP_ORF_PREFIX_RM_RCV))
				prefix_type = ORF_TYPE_PREFIX;
			else
				prefix_type = ORF_TYPE_PREFIX_OLD;

			if (filter->plist[FILTER_IN].plist) {
				if (CHECK_FLAG(peer->af_sflags[afi][safi],
					       PEER_STATUS_ORF_PREFIX_SEND))
					cmgd_route_refresh_send(
						peer, afi, safi, prefix_type,
						REFRESH_DEFER, 1,
						CMGD_ROUTE_REFRESH_NORMAL);
				cmgd_route_refresh_send(
					peer, afi, safi, prefix_type,
					REFRESH_IMMEDIATE, 0,
					CMGD_ROUTE_REFRESH_NORMAL);
			} else {
				if (CHECK_FLAG(peer->af_sflags[afi][safi],
					       PEER_STATUS_ORF_PREFIX_SEND))
					cmgd_route_refresh_send(
						peer, afi, safi, prefix_type,
						REFRESH_IMMEDIATE, 1,
						CMGD_ROUTE_REFRESH_NORMAL);
				else
					cmgd_route_refresh_send(
						peer, afi, safi, 0, 0, 0,
						CMGD_ROUTE_REFRESH_NORMAL);
			}
			return 0;
		}
	}

	if (stype == CMGD_CLEAR_SOFT_IN || stype == CMGD_CLEAR_SOFT_BOTH
	    || stype == CMGD_CLEAR_SOFT_IN_ORF_PREFIX) {
		/* If neighbor has soft reconfiguration inbound flag.
		   Use Adj-RIB-In database. */
		if (CHECK_FLAG(peer->af_flags[afi][safi],
			       PEER_FLAG_SOFT_RECONFIG))
			cmgd_soft_reconfig_in(peer, afi, safi);
		else {
			/* If neighbor has route refresh capability, send route
			   refresh
			   message to the peer. */
			if (CHECK_FLAG(peer->cap, PEER_CAP_REFRESH_OLD_RCV)
			    || CHECK_FLAG(peer->cap, PEER_CAP_REFRESH_NEW_RCV))
				cmgd_route_refresh_send(
					peer, afi, safi, 0, 0, 0,
					CMGD_ROUTE_REFRESH_NORMAL);
			else
				return CMGD_ERR_SOFT_RECONFIG_UNCONFIGURED;
		}
	}
	return 0;
}

/* Display peer uptime.*/
char *peer_uptime(time_t uptime2, char *buf, size_t len, bool use_json,
		  json_object *json)
{
	time_t uptime1, epoch_tbuf;
	struct tm tm;

	/* If there is no connection has been done before print `never'. */
	if (uptime2 == 0) {
		if (use_json) {
			json_object_string_add(json, "peerUptime", "never");
			json_object_int_add(json, "peerUptimeMsec", 0);
		} else
			snprintf(buf, len, "never");
		return buf;
	}

	/* Get current time. */
	uptime1 = cmgd_clock();
	uptime1 -= uptime2;
	gmtime_r(&uptime1, &tm);

	if (uptime1 < ONE_DAY_SECOND)
		snprintf(buf, len, "%02d:%02d:%02d", tm.tm_hour, tm.tm_min,
			 tm.tm_sec);
	else if (uptime1 < ONE_WEEK_SECOND)
		snprintf(buf, len, "%dd%02dh%02dm", tm.tm_yday, tm.tm_hour,
			 tm.tm_min);
	else if (uptime1 < ONE_YEAR_SECOND)
		snprintf(buf, len, "%02dw%dd%02dh", tm.tm_yday / 7,
			 tm.tm_yday - ((tm.tm_yday / 7) * 7), tm.tm_hour);
	else
		snprintf(buf, len, "%02dy%02dw%dd", tm.tm_year - 70,
			 tm.tm_yday / 7,
			 tm.tm_yday - ((tm.tm_yday / 7) * 7));

	if (use_json) {
		epoch_tbuf = time(NULL) - uptime1;
		json_object_string_add(json, "peerUptime", buf);
		json_object_int_add(json, "peerUptimeMsec", uptime1 * 1000);
		json_object_int_add(json, "peerUptimeEstablishedEpoch",
				    epoch_tbuf);
	}

	return buf;
}
#endif 

void cmgd_master_init(struct thread_master *master, const int buffer_size,
		      struct list *addresses)
{
	qobj_init();

	memset(&cmgd_master, 0, sizeof(struct cmgd_master));

	cm = &cmgd_master;
	cm->cmgd = list_new();
	cm->listen_sockets = list_new();
	// cm->port = CMGD_PORT_DEFAULT;
	// cm->addresses = addresses;
	cm->master = master;
	cm->start_time = cmgd_clock();
	// cm->t_rmap_update = NULL;
	// cm->rmap_update_timer = RMAP_DEFAULT_UPDATE_TIMER;
	// cm->v_update_delay = CMGD_UPDATE_DELAY_DEF;
	// cm->v_establish_wait = CMGD_UPDATE_DELAY_DEF;
	cm->terminating = false;
	cm->socket_buffer = buffer_size;
	// cm->wait_for_fib = false;

	// SET_FLAG(cm->flags, BM_FLAG_SEND_EXTRA_DATA_TO_ZEBRA);

	// cmgd_mac_init();
	/* init the rd id space.
	   assign 0th index in the bitfield,
	   so that we start with id 1
	 */
	// bf_init(cm->rd_idspace, UINT16_MAX);
	// bf_assign_zero_index(cm->rd_idspace);

	/* mpls label dynamic allocation pool */
	// cmgd_lp_init(cm->master, &cm->labelpool);

	// cmgd_l3nhg_init();
	// cmgd_evpn_mh_init();
	// QOBJ_REG(bm, cmgd_master);
}

#if 0
/*
 * Free up connected routes and interfaces for a CMGD instance. Invoked upon
 * instance delete (non-default only) or CMGD exit.
 */
static void cmgd_if_finish(struct cmgd *cmgd)
{
	struct vrf *vrf;
	struct interface *ifp;

	vrf = cmgd_vrf_lookup_by_instance_type(cmgd);

	if (cmgd->inst_type == CMGD_INSTANCE_TYPE_VIEW || !vrf)
		return;

	FOR_ALL_INTERFACES (vrf, ifp) {
		struct listnode *c_node, *c_nnode;
		struct connected *c;

		for (ALL_LIST_ELEMENTS(ifp->connected, c_node, c_nnode, c))
			cmgd_connected_delete(cmgd, c);
	}
}

static void cmgd_viewvrf_autocomplete(vector comps, struct cmd_token *token)
{
	struct vrf *vrf = NULL;
	struct listnode *next;
	struct cmgd *cmgd;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name)
		vector_set(comps, XSTRDUP(MTYPE_COMPLETION, vrf->name));

	for (ALL_LIST_ELEMENTS_RO(cm->cmgd, next, cmgd)) {
		if (cmgd->inst_type != CMGD_INSTANCE_TYPE_VIEW)
			continue;

		vector_set(comps, XSTRDUP(MTYPE_COMPLETION, cmgd->name));
	}
}

static void cmgd_instasn_autocomplete(vector comps, struct cmd_token *token)
{
	struct listnode *next, *next2;
	struct cmgd *cmgd, *cmgd2;
	char buf[11];

	for (ALL_LIST_ELEMENTS_RO(cm->cmgd, next, cmgd)) {
		/* deduplicate */
		for (ALL_LIST_ELEMENTS_RO(cm->cmgd, next2, cmgd2)) {
			if (cmgd2->as == cmgd->as)
				break;
			if (cmgd2 == cmgd)
				break;
		}
		if (cmgd2 != cmgd)
			continue;

		snprintf(buf, sizeof(buf), "%u", cmgd->as);
		vector_set(comps, XSTRDUP(MTYPE_COMPLETION, buf));
	}
}

static const struct cmd_variable_handler cmgd_viewvrf_var_handlers[] = {
	{.tokenname = "VIEWVRFNAME", .completions = cmgd_viewvrf_autocomplete},
	{.varname = "instasn", .completions = cmgd_instasn_autocomplete},
	{.completions = NULL},
};

struct frr_pthread *cmgd_pth_io;
struct frr_pthread *cmgd_pth_ka;
#endif

static void cmgd_pthreads_init(void)
{
#if 0
	assert(!cmgd_pth_io);
	assert(!cmgd_pth_ka);

	struct frr_pthread_attr io = {
		.start = frr_pthread_attr_default.start,
		.stop = frr_pthread_attr_default.stop,
	};
	struct frr_pthread_attr ka = {
		.start = cmgd_keepalives_start,
		.stop = cmgd_keepalives_stop,
	};
	cmgd_pth_io = frr_pthread_new(&io, "CMGD I/O thread", "cmgd_io");
	cmgd_pth_ka = frr_pthread_new(&ka, "CMGD Keepalives thread", "cmgd_ka");
#endif
}

void cmgd_pthreads_run(void)
{
#if 0
	frr_pthread_run(cmgd_pth_io, NULL);
	frr_pthread_run(cmgd_pth_ka, NULL);

	/* Wait until threads are ready. */
	frr_pthread_wait_running(cmgd_pth_io);
	frr_pthread_wait_running(cmgd_pth_ka);
#endif
}

void cmgd_pthreads_finish(void)
{
	frr_pthread_stop_all();
}

void cmgd_init(void)
{

	/* allocates some vital data structures used by peer commands in
	 * vty_init */
	vty_init_cmgd();

	/* pre-init pthreads */
	cmgd_pthreads_init();

	/* Initialize databases */
	cmgd_db_init(cm);

	/* Initialize CMGD Transaction module */
	cmgd_trxn_init(cm, cm->master);

	/* Initialize the CMGD Backend Adapter Module */
	cmgd_bcknd_adapter_init(cm->master);
	
	/* Initialize the CMGD Frontend Adapter Module */
	cmgd_frntnd_adapter_init(cm->master, cm);

	/* Start the CMGD Backend Server for clients to connect */
	cmgd_bcknd_server_init(cm->master);

	/* Start the CMGD Frontend Server for clients to connect */
	cmgd_frntnd_server_init(cm->master);

	/* CMGD VTY commands installation.  */
	cmgd_vty_init();
}

void cmgd_terminate(void)
{
#if 0
	struct cmgd *cmgd;
	struct peer *peer;
	struct listnode *node, *nnode;
	struct listnode *mnode, *mnnode;

	QOBJ_UNREG(bm);

	/* Close the listener sockets first as this prevents peers from
	 * attempting
	 * to reconnect on receiving the peer unconfig message. In the presence
	 * of a large number of peers this will ensure that no peer is left with
	 * a dangling connection
	 */
	/* reverse cmgd_master_init */
	cmgd_close();

	if (cm->listen_sockets)
		list_delete(&cm->listen_sockets);

	for (ALL_LIST_ELEMENTS(cm->cmgd, mnode, mnnode, cmgd))
		for (ALL_LIST_ELEMENTS(cmgd->peer, node, nnode, peer))
			if (peer->status == Established
			    || peer->status == OpenSent
			    || peer->status == OpenConfirm)
				cmgd_notify_send(peer, CMGD_NOTIFY_CEASE,
						CMGD_NOTIFY_CEASE_PEER_UNCONFIG);

	if (cm->t_rmap_update)
		CMGD_TIMER_OFF(cm->t_rmap_update);

	cmgd_mac_finish();
#endif

	cmgd_bcknd_server_destroy();
}

#if 0
struct peer *peer_lookup_in_view(struct vty *vty, struct cmgd *cmgd,
				 const char *ip_str, bool use_json)
{
	int ret;
	struct peer *peer;
	union sockunion su;

	/* Get peer sockunion. */
	ret = str2sockunion(ip_str, &su);
	if (ret < 0) {
		peer = peer_lookup_by_conf_if(cmgd, ip_str);
		if (!peer) {
			peer = peer_lookup_by_hostname(cmgd, ip_str);

			if (!peer) {
				if (use_json) {
					json_object *json_no = NULL;
					json_no = json_object_new_object();
					json_object_string_add(
						json_no,
						"malformedAddressOrName",
						ip_str);
					vty_out(vty, "%s\n",
						json_object_to_json_string_ext(
							json_no,
							JSON_C_TO_STRING_PRETTY));
					json_object_free(json_no);
				} else
					vty_out(vty,
						"%% Malformed address or name: %s\n",
						ip_str);
				return NULL;
			}
		}
		return peer;
	}

	/* Peer structure lookup. */
	peer = peer_lookup(cmgd, &su);
	if (!peer) {
		if (use_json) {
			json_object *json_no = NULL;
			json_no = json_object_new_object();
			json_object_string_add(json_no, "warning",
					       "No such neighbor in this view/vrf");
			vty_out(vty, "%s\n",
				json_object_to_json_string_ext(
					json_no, JSON_C_TO_STRING_PRETTY));
			json_object_free(json_no);
		} else
			vty_out(vty, "No such neighbor in this view/vrf\n");
		return NULL;
	}

	return peer;
}

void cmgd_gr_apply_running_config(void)
{
	struct peer *peer = NULL;
	struct cmgd *cmgd = NULL;
	struct listnode *node, *nnode;
	bool gr_router_detected = false;

	if (CMGD_DEBUG(graceful_restart, GRACEFUL_RESTART))
		zlog_debug("[CMGD_GR] %s called !", __func__);

	for (ALL_LIST_ELEMENTS(cm->cmgd, node, nnode, cmgd)) {
		for (ALL_LIST_ELEMENTS(cmgd->peer, node, nnode, peer)) {
			cmgd_peer_gr_flags_update(peer);
			if (CHECK_FLAG(peer->flags, PEER_FLAG_GRACEFUL_RESTART))
				gr_router_detected = true;
		}

		if (gr_router_detected
		    && cmgd->present_zebra_gr_state == ZEBRA_GR_DISABLE) {
			cmgd_zebra_send_capabilities(cmgd, true);
		} else if (!gr_router_detected
			   && cmgd->present_zebra_gr_state == ZEBRA_GR_ENABLE) {
			cmgd_zebra_send_capabilities(cmgd, false);
		}

		gr_router_detected = false;
	}
}
#endif
