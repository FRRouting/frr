// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2003 Yasuhiro Ohara
 */

#include <zebra.h>

#include "log.h"
#include "memory.h"
#include "vty.h"
#include "linklist.h"
#include "prefix.h"
#include "table.h"
#include "frrevent.h"
#include "command.h"
#include "defaults.h"
#include "lib/json.h"
#include "lib_errors.h"

#include "ospf6_proto.h"
#include "ospf6_message.h"
#include "ospf6_lsa.h"
#include "ospf6_lsdb.h"
#include "ospf6_route.h"
#include "ospf6_zebra.h"

#include "ospf6_top.h"
#include "ospf6_area.h"
#include "ospf6_interface.h"
#include "ospf6_neighbor.h"
#include "ospf6_network.h"

#include "ospf6_flood.h"
#include "ospf6_asbr.h"
#include "ospf6_abr.h"
#include "ospf6_intra.h"
#include "ospf6_spf.h"
#include "ospf6d.h"
#include "ospf6_gr.h"
#include "lib/json.h"
#include "ospf6_nssa.h"
#include "ospf6_auth_trailer.h"

DEFINE_MTYPE_STATIC(OSPF6D, OSPF6_TOP, "OSPF6 top");

DEFINE_QOBJ_TYPE(ospf6);

FRR_CFG_DEFAULT_BOOL(OSPF6_LOG_ADJACENCY_CHANGES,
	{ .val_bool = true, .match_profile = "datacenter", },
	{ .val_bool = false },
);

#include "ospf6d/ospf6_top_clippy.c"

/* global ospf6d variable */
static struct ospf6_master ospf6_master;
struct ospf6_master *om6;

static void ospf6_disable(struct ospf6 *o);

static void ospf6_add(struct ospf6 *ospf6)
{
	listnode_add(om6->ospf6, ospf6);
}

static void ospf6_del(struct ospf6 *ospf6)
{
	listnode_delete(om6->ospf6, ospf6);
}

const char *ospf6_vrf_id_to_name(vrf_id_t vrf_id)
{
	struct vrf *vrf = vrf_lookup_by_id(vrf_id);

	return vrf ? vrf->name : "NIL";
}

/* Link OSPF instance to VRF. */
void ospf6_vrf_link(struct ospf6 *ospf6, struct vrf *vrf)
{
	ospf6->vrf_id = vrf->vrf_id;
	if (vrf->info != (void *)ospf6)
		vrf->info = (void *)ospf6;
}

/* Unlink OSPF instance from VRF. */
void ospf6_vrf_unlink(struct ospf6 *ospf6, struct vrf *vrf)
{
	if (vrf->info == (void *)ospf6)
		vrf->info = NULL;
	ospf6->vrf_id = VRF_UNKNOWN;
}

struct ospf6 *ospf6_lookup_by_vrf_id(vrf_id_t vrf_id)
{
	struct vrf *vrf = NULL;

	vrf = vrf_lookup_by_id(vrf_id);
	if (!vrf)
		return NULL;
	return (vrf->info) ? (struct ospf6 *)vrf->info : NULL;
}

struct ospf6 *ospf6_lookup_by_vrf_name(const char *name)
{
	struct ospf6 *o = NULL;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(om6->ospf6, node, nnode, o)) {
		if (((o->name == NULL && name == NULL)
		     || (o->name && name && strcmp(o->name, name) == 0)))
			return o;
	}
	return NULL;
}

/* This is hook function for vrf create called as part of vrf_init */
static int ospf6_vrf_new(struct vrf *vrf)
{
	return 0;
}

/* This is hook function for vrf delete call as part of vrf_init */
static int ospf6_vrf_delete(struct vrf *vrf)
{
	return 0;
}

static void ospf6_set_redist_vrf_bitmaps(struct ospf6 *ospf6, bool set)
{
	int type;
	struct list *red_list;

	for (type = 0; type < ZEBRA_ROUTE_MAX; type++) {
		red_list = ospf6->redist[type];
		if (!red_list)
			continue;
		if (IS_OSPF6_DEBUG_ZEBRA(RECV))
			zlog_debug(
				"%s: setting redist vrf %d bitmap for type %d",
				__func__, ospf6->vrf_id, type);
		if (set)
			vrf_bitmap_set(&zclient->redist[AFI_IP6][type],
				       ospf6->vrf_id);
		else
			vrf_bitmap_unset(&zclient->redist[AFI_IP6][type],
					 ospf6->vrf_id);
	}

	red_list = ospf6->redist[DEFAULT_ROUTE];
	if (red_list) {
		if (set)
			vrf_bitmap_set(&zclient->default_information[AFI_IP6],
				       ospf6->vrf_id);
		else
			vrf_bitmap_unset(&zclient->default_information[AFI_IP6],
					 ospf6->vrf_id);
	}
}

/* Disable OSPF6 VRF instance */
static int ospf6_vrf_disable(struct vrf *vrf)
{
	struct ospf6 *ospf6 = NULL;

	if (vrf->vrf_id == VRF_DEFAULT)
		return 0;

	ospf6 = ospf6_lookup_by_vrf_name(vrf->name);
	if (ospf6) {
		ospf6_zebra_vrf_deregister(ospf6);

		ospf6_set_redist_vrf_bitmaps(ospf6, false);

		/* We have instance configured, unlink
		 * from VRF and make it "down".
		 */
		ospf6_vrf_unlink(ospf6, vrf);
		event_cancel(&ospf6->t_ospf6_receive);
		close(ospf6->fd);
		ospf6->fd = -1;
	}

	/* Note: This is a callback, the VRF will be deleted by the caller. */
	return 0;
}

/* Enable OSPF6 VRF instance */
static int ospf6_vrf_enable(struct vrf *vrf)
{
	struct ospf6 *ospf6 = NULL;
	vrf_id_t old_vrf_id;
	int ret = 0;

	ospf6 = ospf6_lookup_by_vrf_name(vrf->name);
	if (ospf6) {
		old_vrf_id = ospf6->vrf_id;
		/* We have instance configured, link to VRF and make it "up". */
		ospf6_vrf_link(ospf6, vrf);

		if (old_vrf_id != ospf6->vrf_id) {
			ospf6_set_redist_vrf_bitmaps(ospf6, true);

			/* start zebra redist to us for new vrf */
			ospf6_zebra_vrf_register(ospf6);

			ret = ospf6_serv_sock(ospf6);
			if (ret < 0 || ospf6->fd <= 0)
				return 0;
			event_add_read(master, ospf6_receive, ospf6, ospf6->fd,
				       &ospf6->t_ospf6_receive);

			ospf6_router_id_update(ospf6, true);
		}
	}

	return 0;
}

void ospf6_vrf_init(void)
{
	vrf_init(ospf6_vrf_new, ospf6_vrf_enable, ospf6_vrf_disable,
		 ospf6_vrf_delete);

	vrf_cmd_init(NULL);
}

static void ospf6_top_lsdb_hook_add(struct ospf6_lsa *lsa)
{
	switch (ntohs(lsa->header->type)) {
	case OSPF6_LSTYPE_AS_EXTERNAL:
		ospf6_asbr_lsa_add(lsa);
		break;

	default:
		break;
	}
}

static void ospf6_top_lsdb_hook_remove(struct ospf6_lsa *lsa)
{
	switch (ntohs(lsa->header->type)) {
	case OSPF6_LSTYPE_AS_EXTERNAL:
		ospf6_asbr_lsa_remove(lsa, NULL);
		break;

	default:
		break;
	}
}

static void ospf6_top_route_hook_add(struct ospf6_route *route)
{
	struct ospf6 *ospf6 = NULL;
	struct ospf6_area *oa = NULL;

	if (route->table->scope_type == OSPF6_SCOPE_TYPE_GLOBAL)
		ospf6 = route->table->scope;
	else if (route->table->scope_type == OSPF6_SCOPE_TYPE_AREA) {
		oa = (struct ospf6_area *)route->table->scope;
		ospf6 = oa->ospf6;
	} else {
		if (IS_OSPF6_DEBUG_EXAMIN(AS_EXTERNAL)
		    || IS_OSPF6_DEBUG_BROUTER)
			zlog_debug(
				"%s: Route is not GLOBAL or scope is not of TYPE_AREA: %pFX",
				__func__, &route->prefix);
		return;
	}

	ospf6_abr_originate_summary(route, ospf6);
	ospf6_zebra_route_update_add(route, ospf6);
}

static void ospf6_top_route_hook_remove(struct ospf6_route *route)
{
	struct ospf6 *ospf6 = NULL;
	struct ospf6_area *oa = NULL;

	if (route->table->scope_type == OSPF6_SCOPE_TYPE_GLOBAL)
		ospf6 = route->table->scope;
	else if (route->table->scope_type == OSPF6_SCOPE_TYPE_AREA) {
		oa = (struct ospf6_area *)route->table->scope;
		ospf6 = oa->ospf6;
	} else {
		if (IS_OSPF6_DEBUG_EXAMIN(AS_EXTERNAL)
		    || IS_OSPF6_DEBUG_BROUTER)
			zlog_debug(
				"%s: Route is not GLOBAL or scope is not of TYPE_AREA: %pFX",
				__func__, &route->prefix);
		return;
	}

	route->flag |= OSPF6_ROUTE_REMOVE;
	ospf6_abr_originate_summary(route, ospf6);
	ospf6_zebra_route_update_remove(route, ospf6);
}

static void ospf6_top_brouter_hook_add(struct ospf6_route *route)
{
	struct ospf6 *ospf6 = route->table->scope;

	if (IS_OSPF6_DEBUG_EXAMIN(AS_EXTERNAL) ||
	    IS_OSPF6_DEBUG_BROUTER) {
		uint32_t brouter_id;
		char brouter_name[16];

		brouter_id = ADV_ROUTER_IN_PREFIX(&route->prefix);
		inet_ntop(AF_INET, &brouter_id, brouter_name,
			  sizeof(brouter_name));
		zlog_debug("%s: brouter %s add with adv router %x nh count %u",
			   __func__, brouter_name,
			   route->path.origin.adv_router,
			   listcount(route->nh_list));
	}
	ospf6_abr_examin_brouter(ADV_ROUTER_IN_PREFIX(&route->prefix), route,
				 ospf6);
	ospf6_asbr_lsentry_add(route, ospf6);
	ospf6_abr_originate_summary(route, ospf6);
}

static void ospf6_top_brouter_hook_remove(struct ospf6_route *route)
{
	struct ospf6 *ospf6 = route->table->scope;

	if (IS_OSPF6_DEBUG_EXAMIN(AS_EXTERNAL) ||
	    IS_OSPF6_DEBUG_BROUTER) {
		uint32_t brouter_id;
		char brouter_name[16];

		brouter_id = ADV_ROUTER_IN_PREFIX(&route->prefix);
		inet_ntop(AF_INET, &brouter_id, brouter_name,
			  sizeof(brouter_name));
		zlog_debug("%s: brouter %p %s del with adv router %x nh %u",
			   __func__, (void *)route, brouter_name,
			   route->path.origin.adv_router,
			   listcount(route->nh_list));
	}
	route->flag |= OSPF6_ROUTE_REMOVE;
	ospf6_abr_examin_brouter(ADV_ROUTER_IN_PREFIX(&route->prefix), route,
				 ospf6);
	ospf6_asbr_lsentry_remove(route, ospf6);
	ospf6_abr_originate_summary(route, ospf6);
}

static struct ospf6 *ospf6_create(const char *name)
{
	struct ospf6 *o;
	struct vrf *vrf = NULL;

	o = XCALLOC(MTYPE_OSPF6_TOP, sizeof(struct ospf6));

	vrf = vrf_lookup_by_name(name);
	if (vrf) {
		o->vrf_id = vrf->vrf_id;
	} else
		o->vrf_id = VRF_UNKNOWN;

	/* Freed in ospf6_delete */
	o->name = XSTRDUP(MTYPE_OSPF6_TOP, name);
	if (vrf)
		ospf6_vrf_link(o, vrf);

	ospf6_zebra_vrf_register(o);

	/* initialize */
	monotime(&o->starttime);
	o->area_list = list_new();
	o->area_list->cmp = ospf6_area_cmp;
	o->lsdb = ospf6_lsdb_create(o);
	o->lsdb_self = ospf6_lsdb_create(o);
	o->lsdb->hook_add = ospf6_top_lsdb_hook_add;
	o->lsdb->hook_remove = ospf6_top_lsdb_hook_remove;

	o->spf_delay = OSPF_SPF_DELAY_DEFAULT;
	o->spf_holdtime = OSPF_SPF_HOLDTIME_DEFAULT;
	o->spf_max_holdtime = OSPF_SPF_MAX_HOLDTIME_DEFAULT;
	o->spf_hold_multiplier = 1;

	o->default_originate = DEFAULT_ORIGINATE_NONE;
	o->redistribute = 0;
	/* LSA timers value init */
	o->lsa_minarrival = OSPF_MIN_LS_ARRIVAL;

	o->route_table = OSPF6_ROUTE_TABLE_CREATE(GLOBAL, ROUTES);
	o->route_table->scope = o;
	o->route_table->hook_add = ospf6_top_route_hook_add;
	o->route_table->hook_remove = ospf6_top_route_hook_remove;

	o->brouter_table = OSPF6_ROUTE_TABLE_CREATE(GLOBAL, BORDER_ROUTERS);
	o->brouter_table->scope = o;
	o->brouter_table->hook_add = ospf6_top_brouter_hook_add;
	o->brouter_table->hook_remove = ospf6_top_brouter_hook_remove;

	o->external_table = OSPF6_ROUTE_TABLE_CREATE(GLOBAL, EXTERNAL_ROUTES);
	o->external_table->scope = o;
	/* Setting this to 1, so that the LS ID 0 can be considered as invalid
	 * for self originated external LSAs. This helps in differentiating if
	 * an LSA is originated for any route or not in the route data.
	 * rt->route_option->id is by default 0
	 * Consider a route having id as 0 and prefix as 1::1, an external LSA
	 * is originated with ID 0.0.0.0. Now consider another route 2::2
	 * and for this LSA was not originated because of some configuration
	 * but the ID field rt->route_option->id is still 0.Consider now this
	 * 2::2 is being deleted, it will search LSA with LS ID as 0 and it
	 * will find the LSA and hence delete it but the LSA belonged to prefix
	 * 1::1, this happened because of LS ID 0.
	 */
	o->external_id = OSPF6_EXT_INIT_LS_ID;

	o->write_oi_count = OSPF6_WRITE_INTERFACE_COUNT_DEFAULT;
	o->ref_bandwidth = OSPF6_REFERENCE_BANDWIDTH;

	o->distance_table = route_table_init();

	o->rt_aggr_tbl = route_table_init();
	o->aggr_delay_interval = OSPF6_EXTL_AGGR_DEFAULT_DELAY;
	o->aggr_action = OSPF6_ROUTE_AGGR_NONE;

	o->fd = -1;

	o->max_multipath = MULTIPATH_NUM;

	o->oi_write_q = list_new();

	ospf6_gr_helper_init(o);
	QOBJ_REG(o, ospf6);

	/* Make ospf protocol socket. */
	ospf6_serv_sock(o);

	/* If sequence number is stored in persistent storage, read it.
	 */
	if (ospf6_auth_nvm_file_exist() == OSPF6_AUTH_FILE_EXIST) {
		ospf6_auth_seqno_nvm_read(o);
		o->seqnum_h = o->seqnum_h + 1;
		ospf6_auth_seqno_nvm_update(o);
	} else {
		o->seqnum_l = o->seqnum_h = 0;
		ospf6_auth_seqno_nvm_update(o);
	}

	return o;
}

struct ospf6 *ospf6_instance_create(const char *name)
{
	struct ospf6 *ospf6;
	struct vrf *vrf;
	struct interface *ifp;

	ospf6 = ospf6_create(name);
	if (DFLT_OSPF6_LOG_ADJACENCY_CHANGES)
		SET_FLAG(ospf6->config_flags, OSPF6_LOG_ADJACENCY_CHANGES);
	if (ospf6->router_id == 0)
		ospf6_router_id_update(ospf6, true);
	ospf6_add(ospf6);

	/*
	 * Read from non-volatile memory whether this instance is performing a
	 * graceful restart or not.
	 */
	ospf6_gr_nvm_read(ospf6);

	if (ospf6->vrf_id != VRF_UNKNOWN) {
		vrf = vrf_lookup_by_id(ospf6->vrf_id);
		FOR_ALL_INTERFACES (vrf, ifp) {
			if (ifp->info)
				ospf6_interface_start(ifp->info);
		}
	}
	if (ospf6->fd < 0)
		return ospf6;

	event_add_read(master, ospf6_receive, ospf6, ospf6->fd,
		       &ospf6->t_ospf6_receive);

	return ospf6;
}

void ospf6_delete(struct ospf6 *o)
{
	struct listnode *node, *nnode;
	struct route_node *rn = NULL;
	struct ospf6_area *oa;
	struct vrf *vrf;
	struct ospf6_external_aggr_rt *aggr;

	QOBJ_UNREG(o);

	ospf6_gr_helper_deinit(o);
	if (!o->gr_info.prepare_in_progress)
		ospf6_flush_self_originated_lsas_now(o);
	XFREE(MTYPE_TMP, o->gr_info.exit_reason);
	ospf6_disable(o);
	ospf6_del(o);

	ospf6_zebra_vrf_deregister(o);

	ospf6_serv_close(&o->fd);

	for (ALL_LIST_ELEMENTS(o->area_list, node, nnode, oa))
		ospf6_area_delete(oa);


	list_delete(&o->area_list);

	ospf6_lsdb_delete(o->lsdb);
	ospf6_lsdb_delete(o->lsdb_self);

	ospf6_route_table_delete(o->route_table);
	ospf6_route_table_delete(o->brouter_table);

	ospf6_route_table_delete(o->external_table);

	ospf6_distance_reset(o);
	route_table_finish(o->distance_table);
	list_delete(&o->oi_write_q);

	if (o->vrf_id != VRF_UNKNOWN) {
		vrf = vrf_lookup_by_id(o->vrf_id);
		if (vrf)
			ospf6_vrf_unlink(o, vrf);
	}

	for (rn = route_top(o->rt_aggr_tbl); rn; rn = route_next(rn))
		if (rn->info) {
			aggr = rn->info;
			ospf6_asbr_summary_config_delete(o, rn);
			ospf6_external_aggregator_free(aggr);
		}
	route_table_finish(o->rt_aggr_tbl);

	XFREE(MTYPE_OSPF6_TOP, o->name);
	XFREE(MTYPE_OSPF6_TOP, o);
}

static void ospf6_disable(struct ospf6 *o)
{
	struct listnode *node, *nnode;
	struct ospf6_area *oa;

	if (!CHECK_FLAG(o->flag, OSPF6_DISABLED)) {
		SET_FLAG(o->flag, OSPF6_DISABLED);

		for (ALL_LIST_ELEMENTS(o->area_list, node, nnode, oa))
			ospf6_area_disable(oa);

		/* XXX: This also changes persistent settings */
		/* Unregister redistribution */
		ospf6_asbr_redistribute_disable(o);

		ospf6_lsdb_remove_all(o->lsdb);
		ospf6_route_remove_all(o->route_table);
		ospf6_route_remove_all(o->brouter_table);

		EVENT_OFF(o->maxage_remover);
		EVENT_OFF(o->t_spf_calc);
		EVENT_OFF(o->t_ase_calc);
		EVENT_OFF(o->t_distribute_update);
		EVENT_OFF(o->t_ospf6_receive);
		EVENT_OFF(o->t_external_aggr);
		EVENT_OFF(o->gr_info.t_grace_period);
		EVENT_OFF(o->t_write);
		EVENT_OFF(o->t_abr_task);
	}
}

void ospf6_master_init(struct event_loop *master)
{
	memset(&ospf6_master, 0, sizeof(ospf6_master));

	om6 = &ospf6_master;
	om6->ospf6 = list_new();
	om6->master = master;
}

static void ospf6_maxage_remover(struct event *thread)
{
	struct ospf6 *o = (struct ospf6 *)EVENT_ARG(thread);
	struct ospf6_area *oa;
	struct ospf6_interface *oi;
	struct ospf6_neighbor *on;
	struct listnode *i, *j, *k;
	int reschedule = 0;

	for (ALL_LIST_ELEMENTS_RO(o->area_list, i, oa)) {
		for (ALL_LIST_ELEMENTS_RO(oa->if_list, j, oi)) {
			for (ALL_LIST_ELEMENTS_RO(oi->neighbor_list, k, on)) {
				if (on->state != OSPF6_NEIGHBOR_EXCHANGE
				    && on->state != OSPF6_NEIGHBOR_LOADING)
					continue;

				ospf6_maxage_remove(o);
				return;
			}
		}
	}

	for (ALL_LIST_ELEMENTS_RO(o->area_list, i, oa)) {
		for (ALL_LIST_ELEMENTS_RO(oa->if_list, j, oi)) {
			if (ospf6_lsdb_maxage_remover(oi->lsdb)) {
				reschedule = 1;
			}
		}

		if (ospf6_lsdb_maxage_remover(oa->lsdb)) {
			reschedule = 1;
		}
	}

	if (ospf6_lsdb_maxage_remover(o->lsdb)) {
		reschedule = 1;
	}

	if (reschedule) {
		ospf6_maxage_remove(o);
	}
}

void ospf6_maxage_remove(struct ospf6 *o)
{
	if (o)
		event_add_timer(master, ospf6_maxage_remover, o,
				OSPF_LSA_MAXAGE_REMOVE_DELAY_DEFAULT,
				&o->maxage_remover);
}

bool ospf6_router_id_update(struct ospf6 *ospf6, bool init)
{
	in_addr_t new_router_id;
	struct listnode *node;
	struct ospf6_area *oa;

	if (!ospf6)
		return true;

	if (ospf6->router_id_static != 0)
		new_router_id = ospf6->router_id_static;
	else
		new_router_id = ospf6->router_id_zebra;

	if (ospf6->router_id == new_router_id)
		return true;

	if (!init)
		for (ALL_LIST_ELEMENTS_RO(ospf6->area_list, node, oa)) {
			if (oa->full_nbrs) {
				zlog_err(
					"%s: cannot update router-id. Run the \"clear ipv6 ospf6 process\" command",
					__func__);
				return false;
			}
		}

	ospf6->router_id = new_router_id;
	return true;
}

/* start ospf6 */
DEFUN_NOSH(router_ospf6, router_ospf6_cmd, "router ospf6 [vrf NAME]",
	   ROUTER_STR OSPF6_STR VRF_CMD_HELP_STR)
{
	struct ospf6 *ospf6;
	const char *vrf_name = VRF_DEFAULT_NAME;
	int idx_vrf = 0;

	if (argv_find(argv, argc, "vrf", &idx_vrf)) {
		vrf_name = argv[idx_vrf + 1]->arg;
	}

	ospf6 = ospf6_lookup_by_vrf_name(vrf_name);
	if (ospf6 == NULL)
		ospf6 = ospf6_instance_create(vrf_name);

	/* set current ospf point. */
	VTY_PUSH_CONTEXT(OSPF6_NODE, ospf6);

	return CMD_SUCCESS;
}

/* stop ospf6 */
DEFUN(no_router_ospf6, no_router_ospf6_cmd, "no router ospf6 [vrf NAME]",
      NO_STR ROUTER_STR OSPF6_STR VRF_CMD_HELP_STR)
{
	struct ospf6 *ospf6;
	const char *vrf_name = VRF_DEFAULT_NAME;
	int idx_vrf = 0;

	if (argv_find(argv, argc, "vrf", &idx_vrf)) {
		vrf_name = argv[idx_vrf + 1]->arg;
	}

	ospf6 = ospf6_lookup_by_vrf_name(vrf_name);
	if (ospf6 == NULL)
		vty_out(vty, "OSPFv3 is not configured\n");
	else {
		if (ospf6->gr_info.restart_support)
			ospf6_gr_nvm_delete(ospf6);

		ospf6_delete(ospf6);
		ospf6 = NULL;
	}

	/* return to config node . */
	VTY_PUSH_CONTEXT_NULL(CONFIG_NODE);

	return CMD_SUCCESS;
}

static void ospf6_db_clear(struct ospf6 *ospf6)
{
	struct ospf6_interface *oi;
	struct interface *ifp;
	struct vrf *vrf = vrf_lookup_by_id(ospf6->vrf_id);
	struct listnode *node, *nnode;
	struct ospf6_area *oa;

	FOR_ALL_INTERFACES (vrf, ifp) {
		if (if_is_operative(ifp) && ifp->info != NULL) {
			oi = (struct ospf6_interface *)ifp->info;
			ospf6_lsdb_remove_all(oi->lsdb);
			ospf6_lsdb_remove_all(oi->lsdb_self);
			ospf6_lsdb_remove_all(oi->lsupdate_list);
			ospf6_lsdb_remove_all(oi->lsack_list);
		}
	}

	for (ALL_LIST_ELEMENTS(ospf6->area_list, node, nnode, oa)) {
		ospf6_lsdb_remove_all(oa->lsdb);
		ospf6_lsdb_remove_all(oa->lsdb_self);

		ospf6_spf_table_finish(oa->spf_table);
		ospf6_route_remove_all(oa->route_table);
	}

	ospf6_lsdb_remove_all(ospf6->lsdb);
	ospf6_lsdb_remove_all(ospf6->lsdb_self);
	ospf6_route_remove_all(ospf6->route_table);
	ospf6_route_remove_all(ospf6->brouter_table);
}

static void ospf6_process_reset(struct ospf6 *ospf6)
{
	struct interface *ifp;
	struct vrf *vrf = vrf_lookup_by_id(ospf6->vrf_id);

	ospf6_unset_all_aggr_flag(ospf6);
	ospf6_flush_self_originated_lsas_now(ospf6);
	ospf6->inst_shutdown = 0;
	ospf6_db_clear(ospf6);

	ospf6_asbr_redistribute_reset(ospf6);
	FOR_ALL_INTERFACES (vrf, ifp)
		ospf6_interface_clear(ifp);
}

DEFPY (clear_router_ospf6,
       clear_router_ospf6_cmd,
       "clear ipv6 ospf6 process [vrf NAME$name]",
       CLEAR_STR
       IP6_STR
       OSPF6_STR
       "Reset OSPF Process\n"
       VRF_CMD_HELP_STR)
{
	struct ospf6 *ospf6;
	const char *vrf_name = VRF_DEFAULT_NAME;

	if (name != NULL)
		vrf_name = name;

	ospf6 = ospf6_lookup_by_vrf_name(vrf_name);
	if (ospf6 == NULL) {
		vty_out(vty, "OSPFv3 is not configured\n");
	} else {
		ospf6_router_id_update(ospf6, true);
		ospf6_process_reset(ospf6);
	}

	return CMD_SUCCESS;
}

/* change Router_ID commands. */
DEFUN(ospf6_router_id,
      ospf6_router_id_cmd,
      "ospf6 router-id A.B.C.D",
      OSPF6_STR
      "Configure OSPF6 Router-ID\n"
      V4NOTATION_STR)
{
	VTY_DECLVAR_CONTEXT(ospf6, o);
	int idx = 0;
	int ret;
	const char *router_id_str;
	uint32_t router_id;

	argv_find(argv, argc, "A.B.C.D", &idx);
	router_id_str = argv[idx]->arg;

	ret = inet_pton(AF_INET, router_id_str, &router_id);
	if (ret == 0) {
		vty_out(vty, "malformed OSPF Router-ID: %s\n", router_id_str);
		return CMD_SUCCESS;
	}

	o->router_id_static = router_id;

	if (ospf6_router_id_update(o, false))
		ospf6_process_reset(o);
	else
		vty_out(vty,
			"For this router-id change to take effect run the \"clear ipv6 ospf6 process\" command\n");

	return CMD_SUCCESS;
}

DEFUN(no_ospf6_router_id,
      no_ospf6_router_id_cmd,
      "no ospf6 router-id [A.B.C.D]",
      NO_STR OSPF6_STR
      "Configure OSPF6 Router-ID\n"
      V4NOTATION_STR)
{
	VTY_DECLVAR_CONTEXT(ospf6, o);

	o->router_id_static = 0;


	if (ospf6_router_id_update(o, false))
		ospf6_process_reset(o);
	else
		vty_out(vty,
			"For this router-id change to take effect run the \"clear ipv6 ospf6 process\" command\n");

	return CMD_SUCCESS;
}

DEFUN (ospf6_log_adjacency_changes,
       ospf6_log_adjacency_changes_cmd,
       "log-adjacency-changes",
       "Log changes in adjacency state\n")
{
	VTY_DECLVAR_CONTEXT(ospf6, ospf6);

	SET_FLAG(ospf6->config_flags, OSPF6_LOG_ADJACENCY_CHANGES);
	UNSET_FLAG(ospf6->config_flags, OSPF6_LOG_ADJACENCY_DETAIL);
	return CMD_SUCCESS;
}

DEFUN (ospf6_log_adjacency_changes_detail,
       ospf6_log_adjacency_changes_detail_cmd,
       "log-adjacency-changes detail",
       "Log changes in adjacency state\n"
       "Log all state changes\n")
{
	VTY_DECLVAR_CONTEXT(ospf6, ospf6);

	SET_FLAG(ospf6->config_flags, OSPF6_LOG_ADJACENCY_CHANGES);
	SET_FLAG(ospf6->config_flags, OSPF6_LOG_ADJACENCY_DETAIL);
	return CMD_SUCCESS;
}

DEFUN (no_ospf6_log_adjacency_changes,
       no_ospf6_log_adjacency_changes_cmd,
       "no log-adjacency-changes",
       NO_STR
       "Log changes in adjacency state\n")
{
	VTY_DECLVAR_CONTEXT(ospf6, ospf6);

	UNSET_FLAG(ospf6->config_flags, OSPF6_LOG_ADJACENCY_DETAIL);
	UNSET_FLAG(ospf6->config_flags, OSPF6_LOG_ADJACENCY_CHANGES);
	return CMD_SUCCESS;
}

DEFUN (no_ospf6_log_adjacency_changes_detail,
       no_ospf6_log_adjacency_changes_detail_cmd,
       "no log-adjacency-changes detail",
       NO_STR
       "Log changes in adjacency state\n"
       "Log all state changes\n")
{
	VTY_DECLVAR_CONTEXT(ospf6, ospf6);

	UNSET_FLAG(ospf6->config_flags, OSPF6_LOG_ADJACENCY_DETAIL);
	return CMD_SUCCESS;
}

static void ospf6_reinstall_routes(struct ospf6 *ospf6)
{
	struct ospf6_route *route;

	for (route = ospf6_route_head(ospf6->route_table); route;
	     route = ospf6_route_next(route))
		ospf6_zebra_route_update_add(route, ospf6);
}

DEFPY (ospf6_send_extra_data,
       ospf6_send_extra_data_cmd,
       "[no] ospf6 send-extra-data zebra",
       NO_STR
       OSPF6_STR
       "Extra data to Zebra for display/use\n"
       "To zebra\n")
{
	VTY_DECLVAR_CONTEXT(ospf6, ospf6);

	if (no
	    && CHECK_FLAG(ospf6->config_flags,
			  OSPF6_SEND_EXTRA_DATA_TO_ZEBRA)) {
		UNSET_FLAG(ospf6->config_flags, OSPF6_SEND_EXTRA_DATA_TO_ZEBRA);
		ospf6_reinstall_routes(ospf6);
	} else if (!CHECK_FLAG(ospf6->config_flags,
			       OSPF6_SEND_EXTRA_DATA_TO_ZEBRA)) {
		SET_FLAG(ospf6->config_flags, OSPF6_SEND_EXTRA_DATA_TO_ZEBRA);
		ospf6_reinstall_routes(ospf6);
	}

	return CMD_SUCCESS;
}

DEFUN (ospf6_timers_lsa,
       ospf6_timers_lsa_cmd,
       "timers lsa min-arrival (0-600000)",
       "Adjust routing timers\n"
       "OSPF6 LSA timers\n"
       "Minimum delay in receiving new version of a LSA\n"
       "Delay in milliseconds\n")
{
	VTY_DECLVAR_CONTEXT(ospf6, ospf);
	int idx_number = 3;
	unsigned int minarrival;

	minarrival = strtoul(argv[idx_number]->arg, NULL, 10);
	ospf->lsa_minarrival = minarrival;

	return CMD_SUCCESS;
}

DEFUN (no_ospf6_timers_lsa,
       no_ospf6_timers_lsa_cmd,
       "no timers lsa min-arrival [(0-600000)]",
       NO_STR
       "Adjust routing timers\n"
       "OSPF6 LSA timers\n"
       "Minimum delay in receiving new version of a LSA\n"
       "Delay in milliseconds\n")
{
	VTY_DECLVAR_CONTEXT(ospf6, ospf);
	int idx_number = 4;
	unsigned int minarrival;

	if (argc == 5) {
		minarrival = strtoul(argv[idx_number]->arg, NULL, 10);

		if (ospf->lsa_minarrival != minarrival
		    || minarrival == OSPF_MIN_LS_ARRIVAL)
			return CMD_SUCCESS;
	}

	ospf->lsa_minarrival = OSPF_MIN_LS_ARRIVAL;

	return CMD_SUCCESS;
}


DEFUN (ospf6_distance,
       ospf6_distance_cmd,
       "distance (1-255)",
       "Administrative distance\n"
       "OSPF6 Administrative distance\n")
{
	VTY_DECLVAR_CONTEXT(ospf6, o);
	uint8_t distance;

	distance = atoi(argv[1]->arg);
	if (o->distance_all != distance) {
		o->distance_all = distance;
		ospf6_restart_spf(o);
	}

	return CMD_SUCCESS;
}

DEFUN (no_ospf6_distance,
       no_ospf6_distance_cmd,
       "no distance (1-255)",
       NO_STR
       "Administrative distance\n"
       "OSPF6 Administrative distance\n")
{
	VTY_DECLVAR_CONTEXT(ospf6, o);

	if (o->distance_all) {
		o->distance_all = 0;
		ospf6_restart_spf(o);
	}
	return CMD_SUCCESS;
}

DEFUN (ospf6_distance_ospf6,
       ospf6_distance_ospf6_cmd,
       "distance ospf6 {intra-area (1-255)|inter-area (1-255)|external (1-255)}",
       "Administrative distance\n"
       "OSPF6 administrative distance\n"
       "Intra-area routes\n"
       "Distance for intra-area routes\n"
       "Inter-area routes\n"
       "Distance for inter-area routes\n"
       "External routes\n"
       "Distance for external routes\n")
{
	VTY_DECLVAR_CONTEXT(ospf6, o);
	int idx = 0;

	o->distance_intra = 0;
	o->distance_inter = 0;
	o->distance_external = 0;

	if (argv_find(argv, argc, "intra-area", &idx))
		o->distance_intra = atoi(argv[idx + 1]->arg);
	idx = 0;
	if (argv_find(argv, argc, "inter-area", &idx))
		o->distance_inter = atoi(argv[idx + 1]->arg);
	idx = 0;
	if (argv_find(argv, argc, "external", &idx))
		o->distance_external = atoi(argv[idx + 1]->arg);

	return CMD_SUCCESS;
}

DEFUN (no_ospf6_distance_ospf6,
       no_ospf6_distance_ospf6_cmd,
       "no distance ospf6 [{intra-area [(1-255)]|inter-area [(1-255)]|external [(1-255)]}]",
       NO_STR
       "Administrative distance\n"
       "OSPF6 distance\n"
       "Intra-area routes\n"
       "Distance for intra-area routes\n"
       "Inter-area routes\n"
       "Distance for inter-area routes\n"
       "External routes\n"
       "Distance for external routes\n")
{
	VTY_DECLVAR_CONTEXT(ospf6, o);
	int idx = 0;

	if (argv_find(argv, argc, "intra-area", &idx) || argc == 3)
		idx = o->distance_intra = 0;
	if (argv_find(argv, argc, "inter-area", &idx) || argc == 3)
		idx = o->distance_inter = 0;
	if (argv_find(argv, argc, "external", &idx) || argc == 3)
		o->distance_external = 0;

	return CMD_SUCCESS;
}

DEFUN_HIDDEN (ospf6_interface_area,
       ospf6_interface_area_cmd,
       "interface IFNAME area <A.B.C.D|(0-4294967295)>",
       "Enable routing on an IPv6 interface\n"
       IFNAME_STR
       "Specify the OSPF6 area ID\n"
       "OSPF6 area ID in IPv4 address notation\n"
       "OSPF6 area ID in decimal notation\n"
      )
{
	VTY_DECLVAR_CONTEXT(ospf6, ospf6);
	int idx_ifname = 1;
	int idx_ipv4 = 3;
	struct ospf6_area *oa;
	struct ospf6_interface *oi;
	struct interface *ifp;
	uint32_t area_id;
	int format;

	vty_out(vty,
		"This command is deprecated, because it is not VRF-aware.\n");
	vty_out(vty,
		"Please, use \"ipv6 ospf6 area\" on an interface instead.\n");

	/* find/create ospf6 interface */
	ifp = if_get_by_name(argv[idx_ifname]->arg, ospf6->vrf_id, ospf6->name);
	oi = (struct ospf6_interface *)ifp->info;
	if (oi == NULL)
		oi = ospf6_interface_create(ifp);
	if (oi->area) {
		vty_out(vty, "%s already attached to Area %s\n",
			oi->interface->name, oi->area->name);
		return CMD_SUCCESS;
	}

	if (str2area_id(argv[idx_ipv4]->arg, &area_id, &format)) {
		vty_out(vty, "Malformed Area-ID: %s\n", argv[idx_ipv4]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	oi->area_id = area_id;
	oi->area_id_format = format;

	oa = ospf6_area_lookup(area_id, ospf6);
	if (oa == NULL)
		oa = ospf6_area_create(area_id, ospf6, format);

	/* attach interface to area */
	listnode_add(oa->if_list, oi); /* sort ?? */
	oi->area = oa;

	SET_FLAG(oa->flag, OSPF6_AREA_ENABLE);

	/* ospf6 process is currently disabled, not much more to do */
	if (CHECK_FLAG(ospf6->flag, OSPF6_DISABLED))
		return CMD_SUCCESS;

	/* start up */
	ospf6_interface_enable(oi);

	/* If the router is ABR, originate summary routes */
	if (ospf6_check_and_set_router_abr(ospf6)) {
		ospf6_abr_enable_area(oa);
		ospf6_schedule_abr_task(oa->ospf6);
	}

	return CMD_SUCCESS;
}

DEFUN_HIDDEN (no_ospf6_interface_area,
       no_ospf6_interface_area_cmd,
       "no interface IFNAME area <A.B.C.D|(0-4294967295)>",
       NO_STR
       "Disable routing on an IPv6 interface\n"
       IFNAME_STR
       "Specify the OSPF6 area ID\n"
       "OSPF6 area ID in IPv4 address notation\n"
       "OSPF6 area ID in decimal notation\n"
       )
{
	VTY_DECLVAR_CONTEXT(ospf6, ospf6);
	int idx_ifname = 2;
	int idx_ipv4 = 4;
	struct ospf6_interface *oi;
	struct ospf6_area *oa;
	struct interface *ifp;
	uint32_t area_id;

	vty_out(vty,
		"This command is deprecated, because it is not VRF-aware.\n");
	vty_out(vty,
		"Please, use \"no ipv6 ospf6 area\" on an interface instead.\n");

	/* find/create ospf6 interface */
	ifp = if_get_by_name(argv[idx_ifname]->arg, ospf6->vrf_id, ospf6->name);

	if (ifp == NULL) {
		vty_out(vty, "No such interface %s\n", argv[idx_ifname]->arg);
		return CMD_SUCCESS;
	}

	oi = (struct ospf6_interface *)ifp->info;
	if (oi == NULL) {
		vty_out(vty, "Interface %s not enabled\n", ifp->name);
		return CMD_SUCCESS;
	}

	/* parse Area-ID */
	if (inet_pton(AF_INET, argv[idx_ipv4]->arg, &area_id) != 1)
		area_id = htonl(strtoul(argv[idx_ipv4]->arg, NULL, 10));

	/* Verify Area */
	if (oi->area == NULL) {
		vty_out(vty, "%s not attached to area %s\n",
			oi->interface->name, argv[idx_ipv4]->arg);
		return CMD_SUCCESS;
	}

	if (oi->area->area_id != area_id) {
		vty_out(vty, "Wrong Area-ID: %s is attached to area %s\n",
			oi->interface->name, oi->area->name);
		return CMD_SUCCESS;
	}

	ospf6_interface_disable(oi);

	oa = oi->area;
	listnode_delete(oi->area->if_list, oi);
	oi->area = (struct ospf6_area *)NULL;

	/* Withdraw inter-area routes from this area, if necessary */
	if (oa->if_list->count == 0) {
		UNSET_FLAG(oa->flag, OSPF6_AREA_ENABLE);
		ospf6_abr_disable_area(oa);
	}

	oi->area_id = 0;
	oi->area_id_format = OSPF6_AREA_FMT_UNSET;

	return CMD_SUCCESS;
}

DEFUN (ospf6_stub_router_admin,
       ospf6_stub_router_admin_cmd,
       "stub-router administrative",
       "Make router a stub router\n"
       "Administratively applied, for an indefinite period\n")
{
	struct listnode *node;
	struct ospf6_area *oa;

	VTY_DECLVAR_CONTEXT(ospf6, ospf6);

	if (!CHECK_FLAG(ospf6->flag, OSPF6_STUB_ROUTER)) {
		for (ALL_LIST_ELEMENTS_RO(ospf6->area_list, node, oa)) {
			OSPF6_OPT_CLEAR(oa->options, OSPF6_OPT_V6);
			OSPF6_OPT_CLEAR(oa->options, OSPF6_OPT_R);
			OSPF6_ROUTER_LSA_SCHEDULE(oa);
		}
		SET_FLAG(ospf6->flag, OSPF6_STUB_ROUTER);
	}

	return CMD_SUCCESS;
}

DEFUN (no_ospf6_stub_router_admin,
       no_ospf6_stub_router_admin_cmd,
       "no stub-router administrative",
       NO_STR
       "Make router a stub router\n"
       "Administratively applied, for an indefinite period\n")
{
	struct listnode *node;
	struct ospf6_area *oa;

	VTY_DECLVAR_CONTEXT(ospf6, ospf6);
	if (CHECK_FLAG(ospf6->flag, OSPF6_STUB_ROUTER)) {
		for (ALL_LIST_ELEMENTS_RO(ospf6->area_list, node, oa)) {
			OSPF6_OPT_SET(oa->options, OSPF6_OPT_V6);
			OSPF6_OPT_SET(oa->options, OSPF6_OPT_R);
			OSPF6_ROUTER_LSA_SCHEDULE(oa);
		}
		UNSET_FLAG(ospf6->flag, OSPF6_STUB_ROUTER);
	}

	return CMD_SUCCESS;
}

/* Restart OSPF SPF algorithm*/
void ospf6_restart_spf(struct ospf6 *ospf6)
{
	ospf6_route_remove_all(ospf6->route_table);
	ospf6_route_remove_all(ospf6->brouter_table);

	/* Trigger SPF */
	ospf6_spf_schedule(ospf6, OSPF6_SPF_FLAGS_CONFIG_CHANGE);
}

/* Set the max paths */
static void ospf6_maxpath_set(struct ospf6 *ospf6, uint16_t paths)
{
	if (ospf6->max_multipath == paths)
		return;

	ospf6->max_multipath = paths;

	/* Send deletion to zebra to delete all
	 * ospf specific routes and reinitiate
	 * SPF to reflect the new max multipath.
	 */
	ospf6_restart_spf(ospf6);
}

/* Ospf Maximum-paths config support */
DEFUN(ospf6_max_multipath,
      ospf6_max_multipath_cmd,
      "maximum-paths " CMD_RANGE_STR(1, MULTIPATH_NUM),
      "Max no of multiple paths for ECMP support\n"
      "Number of paths\n")
{
	VTY_DECLVAR_CONTEXT(ospf6, ospf6);
	int idx_number = 1;
	int maximum_paths = strtol(argv[idx_number]->arg, NULL, 10);

	ospf6_maxpath_set(ospf6, maximum_paths);

	return CMD_SUCCESS;
}

DEFUN(no_ospf6_max_multipath,
      no_ospf6_max_multipath_cmd,
     "no maximum-paths [" CMD_RANGE_STR(1, MULTIPATH_NUM)"]",
      NO_STR
      "Max no of multiple paths for ECMP support\n"
      "Number of paths\n")
{
	VTY_DECLVAR_CONTEXT(ospf6, ospf6);

	ospf6_maxpath_set(ospf6, MULTIPATH_NUM);

	return CMD_SUCCESS;
}

static void ospf6_show(struct vty *vty, struct ospf6 *o, json_object *json,
		       bool use_json)
{
	struct listnode *n;
	struct ospf6_area *oa;
	char router_id[16], duration[32];
	struct timeval now, running, result;
	char buf[32], rbuf[32];
	json_object *json_areas = NULL;
	const char *adjacency;

	if (use_json) {
		json_areas = json_object_new_object();

		/* process id, router id */
		inet_ntop(AF_INET, &o->router_id, router_id, sizeof(router_id));
		json_object_string_add(json, "routerId", router_id);

		/* running time */
		monotime(&now);
		timersub(&now, &o->starttime, &running);
		timerstring(&running, duration, sizeof(duration));
		json_object_string_add(json, "running", duration);

		/* Redistribute configuration */
		/* XXX */
		json_object_int_add(json, "lsaMinimumArrivalMsecs",
				    o->lsa_minarrival);

		/* Show SPF parameters */
		json_object_int_add(json, "spfScheduleDelayMsecs",
				    o->spf_delay);
		json_object_int_add(json, "holdTimeMinMsecs", o->spf_holdtime);
		json_object_int_add(json, "holdTimeMaxMsecs",
				    o->spf_max_holdtime);
		json_object_int_add(json, "holdTimeMultiplier",
				    o->spf_hold_multiplier);

		json_object_int_add(json, "maximumPaths", o->max_multipath);
		json_object_int_add(json, "preference",
				    o->distance_all
					    ? o->distance_all
					    : ZEBRA_OSPF6_DISTANCE_DEFAULT);

		if (o->ts_spf.tv_sec || o->ts_spf.tv_usec) {
			timersub(&now, &o->ts_spf, &result);
			timerstring(&result, buf, sizeof(buf));
			ospf6_spf_reason_string(o->last_spf_reason, rbuf,
						sizeof(rbuf));
			json_object_boolean_true_add(json, "spfHasRun");
			json_object_string_add(json, "spfLastExecutedMsecs",
					       buf);
			json_object_string_add(json, "spfLastExecutedReason",
					       rbuf);

			json_object_int_add(
				json, "spfLastDurationSecs",
				(long long)o->ts_spf_duration.tv_sec);

			json_object_int_add(
				json, "spfLastDurationMsecs",
				(long long)o->ts_spf_duration.tv_usec);
		} else
			json_object_boolean_false_add(json, "spfHasRun");

		if (event_is_scheduled(o->t_spf_calc)) {
			long time_store;

			json_object_boolean_true_add(json, "spfTimerActive");
			time_store =
				monotime_until(&o->t_spf_calc->u.sands, NULL)
				/ 1000LL;
			json_object_int_add(json, "spfTimerDueInMsecs",
					    time_store);
		} else
			json_object_boolean_false_add(json, "spfTimerActive");

		json_object_boolean_add(json, "routerIsStubRouter",
					CHECK_FLAG(o->flag, OSPF6_STUB_ROUTER));

		/* LSAs */
		json_object_int_add(json, "numberOfAsScopedLsa",
				    o->lsdb->count);
		/* Areas */
		json_object_int_add(json, "numberOfAreaInRouter",
				    listcount(o->area_list));

		json_object_int_add(json, "AuthTrailerHigherSeqNo",
				    o->seqnum_h);
		json_object_int_add(json, "AuthTrailerLowerSeqNo", o->seqnum_l);

		if (CHECK_FLAG(o->config_flags, OSPF6_LOG_ADJACENCY_CHANGES)) {
			if (CHECK_FLAG(o->config_flags,
				       OSPF6_LOG_ADJACENCY_DETAIL))
				adjacency = "LoggedAll";
			else
				adjacency = "Logged";
		} else
			adjacency = "NotLogged";
		json_object_string_add(json, "adjacencyChanges", adjacency);

		for (ALL_LIST_ELEMENTS_RO(o->area_list, n, oa))
			ospf6_area_show(vty, oa, json_areas, use_json);

		json_object_object_add(json, "areas", json_areas);

		vty_out(vty, "%s\n",
			json_object_to_json_string_ext(
				json, JSON_C_TO_STRING_PRETTY));

	} else {
		/* process id, router id */
		inet_ntop(AF_INET, &o->router_id, router_id, sizeof(router_id));
		vty_out(vty, " OSPFv3 Routing Process (0) with Router-ID %s\n",
			router_id);

		/* running time */
		monotime(&now);
		timersub(&now, &o->starttime, &running);
		timerstring(&running, duration, sizeof(duration));
		vty_out(vty, " Running %s\n", duration);

		/* Redistribute configuration */
		/* XXX */
		vty_out(vty, " LSA minimum arrival %d msecs\n",
			o->lsa_minarrival);

		vty_out(vty, " Maximum-paths %u\n", o->max_multipath);
		vty_out(vty, " Administrative distance %u\n",
			o->distance_all ? o->distance_all
					: ZEBRA_OSPF6_DISTANCE_DEFAULT);

		/* Show SPF parameters */
		vty_out(vty,
			" Initial SPF scheduling delay %d millisec(s)\n"
			" Minimum hold time between consecutive SPFs %d millsecond(s)\n"
			" Maximum hold time between consecutive SPFs %d millsecond(s)\n"
			" Hold time multiplier is currently %d\n",
			o->spf_delay, o->spf_holdtime, o->spf_max_holdtime,
			o->spf_hold_multiplier);


		vty_out(vty, " SPF algorithm ");
		if (o->ts_spf.tv_sec || o->ts_spf.tv_usec) {
			timersub(&now, &o->ts_spf, &result);
			timerstring(&result, buf, sizeof(buf));
			ospf6_spf_reason_string(o->last_spf_reason, rbuf,
						sizeof(rbuf));
			vty_out(vty, "last executed %s ago, reason %s\n", buf,
				rbuf);
			vty_out(vty, " Last SPF duration %lld sec %lld usec\n",
				(long long)o->ts_spf_duration.tv_sec,
				(long long)o->ts_spf_duration.tv_usec);
		} else
			vty_out(vty, "has not been run\n");

		threadtimer_string(now, o->t_spf_calc, buf, sizeof(buf));
		vty_out(vty, " SPF timer %s%s\n",
			(event_is_scheduled(o->t_spf_calc) ? "due in " : "is "),
			buf);

		if (CHECK_FLAG(o->flag, OSPF6_STUB_ROUTER))
			vty_out(vty, " Router Is Stub Router\n");

		/* LSAs */
		vty_out(vty, " Number of AS scoped LSAs is %u\n",
			o->lsdb->count);

		/* Areas */
		vty_out(vty, " Number of areas in this router is %u\n",
			listcount(o->area_list));

		vty_out(vty, " Authentication Sequence number info\n");
		vty_out(vty, "  Higher sequence no %u, Lower sequence no %u\n",
			o->seqnum_h, o->seqnum_l);

		if (CHECK_FLAG(o->config_flags, OSPF6_LOG_ADJACENCY_CHANGES)) {
			if (CHECK_FLAG(o->config_flags,
				       OSPF6_LOG_ADJACENCY_DETAIL))
				vty_out(vty,
					" All adjacency changes are logged\n");
			else
				vty_out(vty, " Adjacency changes are logged\n");
		}


		vty_out(vty, "\n");

		for (ALL_LIST_ELEMENTS_RO(o->area_list, n, oa))
			ospf6_area_show(vty, oa, json_areas, use_json);
	}
}

DEFUN(show_ipv6_ospf6_vrfs, show_ipv6_ospf6_vrfs_cmd,
      "show ipv6 ospf6 vrfs [json]",
      SHOW_STR IP6_STR OSPF6_STR "Show OSPF6 VRFs \n" JSON_STR)
{
	bool uj = use_json(argc, argv);
	json_object *json = NULL;
	json_object *json_vrfs = NULL;
	struct ospf6 *ospf6 = NULL;
	struct listnode *node = NULL;
	int count = 0;
	char buf[PREFIX_STRLEN];
	static const char header[] =
		"Name                       Id     RouterId  ";

	if (uj) {
		json = json_object_new_object();
		json_vrfs = json_object_new_object();
	}

	for (ALL_LIST_ELEMENTS_RO(om6->ospf6, node, ospf6)) {
		json_object *json_vrf = NULL;
		const char *name = NULL;
		int64_t vrf_id_ui = 0;
		struct in_addr router_id;

		router_id.s_addr = ospf6->router_id;
		count++;

		if (!uj && count == 1)
			vty_out(vty, "%s\n", header);
		if (uj)
			json_vrf = json_object_new_object();

		if (ospf6->vrf_id == VRF_DEFAULT)
			name = VRF_DEFAULT_NAME;
		else
			name = ospf6->name;

		vrf_id_ui = (ospf6->vrf_id == VRF_UNKNOWN)
				    ? -1
				    : (int64_t)ospf6->vrf_id;

		if (uj) {
			json_object_int_add(json_vrf, "vrfId", vrf_id_ui);
			json_object_string_addf(json_vrf, "routerId", "%pI4",
						&router_id);
			json_object_object_add(json_vrfs, name, json_vrf);

		} else {
			vty_out(vty, "%-25s  %-5d  %-16s  \n", name,
				ospf6->vrf_id,
				inet_ntop(AF_INET, &router_id, buf,
					  sizeof(buf)));
		}
	}

	if (uj) {
		json_object_object_add(json, "vrfs", json_vrfs);
		json_object_int_add(json, "totalVrfs", count);

		vty_json(vty, json);
	} else {
		if (count)
			vty_out(vty, "\nTotal number of OSPF VRFs: %d\n",
				count);
	}

	return CMD_SUCCESS;
}

/* show top level structures */
DEFUN(show_ipv6_ospf6, show_ipv6_ospf6_cmd,
      "show ipv6 ospf6 [vrf <NAME|all>] [json]",
      SHOW_STR IP6_STR OSPF6_STR VRF_CMD_HELP_STR "All VRFs\n" JSON_STR)
{
	struct ospf6 *ospf6;
	struct listnode *node;
	const char *vrf_name = NULL;
	bool all_vrf = false;
	int idx_vrf = 0;

	bool uj = use_json(argc, argv);
	json_object *json = NULL;

	OSPF6_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);

	for (ALL_LIST_ELEMENTS_RO(om6->ospf6, node, ospf6)) {
		if (all_vrf || strcmp(ospf6->name, vrf_name) == 0) {
			if (uj)
				json = json_object_new_object();
			ospf6_show(vty, ospf6, json, uj);

			if (!all_vrf)
				break;
		}
	}

	if (uj)
		json_object_free(json);

	OSPF6_CMD_CHECK_VRF(uj, all_vrf, ospf6);

	return CMD_SUCCESS;
}

DEFUN(show_ipv6_ospf6_route, show_ipv6_ospf6_route_cmd,
      "show ipv6 ospf6 [vrf <NAME|all>] route [<intra-area|inter-area|external-1|external-2|X:X::X:X|X:X::X:X/M|detail|summary>] [json]",
      SHOW_STR IP6_STR OSPF6_STR VRF_CMD_HELP_STR
      "All VRFs\n" ROUTE_STR
      "Display Intra-Area routes\n"
      "Display Inter-Area routes\n"
      "Display Type-1 External routes\n"
      "Display Type-2 External routes\n"
      "Specify IPv6 address\n"
      "Specify IPv6 prefix\n"
      "Detailed information\n"
      "Summary of route table\n" JSON_STR)
{
	struct ospf6 *ospf6;
	struct listnode *node;
	const char *vrf_name = NULL;
	bool all_vrf = false;
	int idx_vrf = 0;
	int idx_arg_start = 4;
	bool uj = use_json(argc, argv);

	OSPF6_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);
	if (idx_vrf > 0)
		idx_arg_start += 2;

	for (ALL_LIST_ELEMENTS_RO(om6->ospf6, node, ospf6)) {
		if (all_vrf || strcmp(ospf6->name, vrf_name) == 0) {
			ospf6_route_table_show(vty, idx_arg_start, argc, argv,
					       ospf6->route_table, uj);

			if (!all_vrf)
				break;
		}
	}

	OSPF6_CMD_CHECK_VRF(uj, all_vrf, ospf6);

	return CMD_SUCCESS;
}

DEFUN(show_ipv6_ospf6_route_match, show_ipv6_ospf6_route_match_cmd,
      "show ipv6 ospf6 [vrf <NAME|all>] route X:X::X:X/M <match|longer> [json]",
      SHOW_STR IP6_STR OSPF6_STR VRF_CMD_HELP_STR
      "All VRFs\n" ROUTE_STR
      "Specify IPv6 prefix\n"
      "Display routes which match the specified route\n"
      "Display routes longer than the specified route\n" JSON_STR)
{
	struct ospf6 *ospf6;
	struct listnode *node;
	const char *vrf_name = NULL;
	bool all_vrf = false;
	int idx_vrf = 0;
	int idx_start_arg = 4;
	bool uj = use_json(argc, argv);

	OSPF6_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);
	if (idx_vrf > 0)
		idx_start_arg += 2;

	for (ALL_LIST_ELEMENTS_RO(om6->ospf6, node, ospf6)) {
		if (all_vrf || strcmp(ospf6->name, vrf_name) == 0) {
			ospf6_route_table_show(vty, idx_start_arg, argc, argv,
					       ospf6->route_table, uj);

			if (!all_vrf)
				break;
		}
	}

	OSPF6_CMD_CHECK_VRF(uj, all_vrf, ospf6);

	return CMD_SUCCESS;
}

DEFUN(show_ipv6_ospf6_route_match_detail,
      show_ipv6_ospf6_route_match_detail_cmd,
      "show ipv6 ospf6 [vrf <NAME|all>] route X:X::X:X/M match detail [json]",
      SHOW_STR IP6_STR OSPF6_STR VRF_CMD_HELP_STR
      "All VRFs\n" ROUTE_STR
      "Specify IPv6 prefix\n"
      "Display routes which match the specified route\n"
      "Detailed information\n" JSON_STR)
{
	struct ospf6 *ospf6;
	struct listnode *node;
	const char *vrf_name = NULL;
	bool all_vrf = false;
	int idx_vrf = 0;
	int idx_start_arg = 4;
	bool uj = use_json(argc, argv);

	OSPF6_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);
	if (idx_vrf > 0)
		idx_start_arg += 2;

	for (ALL_LIST_ELEMENTS_RO(om6->ospf6, node, ospf6)) {
		if (all_vrf || strcmp(ospf6->name, vrf_name) == 0) {
			ospf6_route_table_show(vty, idx_start_arg, argc, argv,
					       ospf6->route_table, uj);

			if (!all_vrf)
				break;
		}
	}

	OSPF6_CMD_CHECK_VRF(uj, all_vrf, ospf6);

	return CMD_SUCCESS;
}

DEFUN(show_ipv6_ospf6_route_type_detail, show_ipv6_ospf6_route_type_detail_cmd,
      "show ipv6 ospf6 [vrf <NAME|all>] route <intra-area|inter-area|external-1|external-2> detail [json]",
      SHOW_STR IP6_STR OSPF6_STR VRF_CMD_HELP_STR
      "All VRFs\n" ROUTE_STR
      "Display Intra-Area routes\n"
      "Display Inter-Area routes\n"
      "Display Type-1 External routes\n"
      "Display Type-2 External routes\n"
      "Detailed information\n" JSON_STR)
{
	struct ospf6 *ospf6;
	struct listnode *node;
	const char *vrf_name = NULL;
	bool all_vrf = false;
	int idx_vrf = 0;
	int idx_start_arg = 4;
	bool uj = use_json(argc, argv);

	OSPF6_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);
	if (idx_vrf > 0)
		idx_start_arg += 2;

	for (ALL_LIST_ELEMENTS_RO(om6->ospf6, node, ospf6)) {
		if (all_vrf || strcmp(ospf6->name, vrf_name) == 0) {
			ospf6_route_table_show(vty, idx_start_arg, argc, argv,
					       ospf6->route_table, uj);

			if (!all_vrf)
				break;
		}
	}

	OSPF6_CMD_CHECK_VRF(uj, all_vrf, ospf6);

	return CMD_SUCCESS;
}

bool ospf6_is_valid_summary_addr(struct vty *vty, struct prefix *p)
{
	/* Default prefix validation*/
	if (is_default_prefix(p)) {
		vty_out(vty,
			"Default address should not be configured as summary address.\n");
		return false;
	}

	/* Host route should not be configured as summary address */
	if (p->prefixlen == IPV6_MAX_BITLEN) {
		vty_out(vty, "Host route should not be configured as summary address.\n");
		return false;
	}

	return true;
}

/* External Route Aggregation */
DEFPY (ospf6_external_route_aggregation,
       ospf6_external_route_aggregation_cmd,
       "summary-address X:X::X:X/M$prefix [tag (1-4294967295)] [{metric (0-16777215) | metric-type (1-2)$mtype}]",
       "External summary address\n"
       "Specify IPv6 prefix\n"
       "Router tag \n"
       "Router tag value\n"
       "Metric \n"
       "Advertised metric for this route\n"
       "OSPFv3 exterior metric type for summarised routes\n"
       "Set OSPFv3 External Type 1/2 metrics\n")
{
	VTY_DECLVAR_CONTEXT(ospf6, ospf6);

	struct prefix p;
	int ret = CMD_SUCCESS;

	p.family = AF_INET6;
	ret = str2prefix(prefix_str, &p);
	if (ret == 0) {
		vty_out(vty, "Malformed prefix\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Apply mask for given prefix. */
	apply_mask(&p);

	if (!ospf6_is_valid_summary_addr(vty, &p))
		return CMD_WARNING_CONFIG_FAILED;

	if (!tag_str)
		tag = 0;

	if (!metric_str)
		metric = -1;

	if (!mtype_str)
		mtype = DEFAULT_METRIC_TYPE;

	ret = ospf6_external_aggr_config_set(ospf6, &p, tag, metric, mtype);
	if (ret == OSPF6_FAILURE) {
		vty_out(vty, "Invalid configuration!!\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

DEFPY(no_ospf6_external_route_aggregation,
      no_ospf6_external_route_aggregation_cmd,
      "no summary-address X:X::X:X/M$prefix [tag (1-4294967295)] [{metric (0-16777215) | metric-type (1-2)}]",
      NO_STR
      "External summary address\n"
      "Specify IPv6 prefix\n"
      "Router tag\n"
      "Router tag value\n"
      "Metric \n"
      "Advertised metric for this route\n"
      "OSPFv3 exterior metric type for summarised routes\n"
      "Set OSPFv3 External Type 1/2 metrics\n")
{
	VTY_DECLVAR_CONTEXT(ospf6, ospf6);

	struct prefix p;
	int ret = CMD_SUCCESS;

	ret = str2prefix(prefix_str, &p);
	if (ret == 0) {
		vty_out(vty, "Malformed prefix\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Apply mask for given prefix. */
	apply_mask(&p);

	if (!ospf6_is_valid_summary_addr(vty, &p))
		return CMD_WARNING_CONFIG_FAILED;

	ret = ospf6_external_aggr_config_unset(ospf6, &p);
	if (ret == OSPF6_INVALID)
		vty_out(vty, "Invalid configuration!!\n");

	return CMD_SUCCESS;
}

DEFPY (ospf6_external_route_aggregation_no_advertise,
       ospf6_external_route_aggregation_no_advertise_cmd,
       "summary-address X:X::X:X/M$prefix no-advertise",
       "External summary address\n"
       "Specify IPv6 prefix\n"
       "Don't advertise summary route \n")
{
	VTY_DECLVAR_CONTEXT(ospf6, ospf6);

	struct prefix p;
	int ret = CMD_SUCCESS;

	ret = str2prefix(prefix_str, &p);
	if (ret == 0) {
		vty_out(vty, "Malformed prefix\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Apply mask for given prefix. */
	apply_mask(&p);

	if (!ospf6_is_valid_summary_addr(vty, &p))
		return CMD_WARNING_CONFIG_FAILED;

	ret = ospf6_asbr_external_rt_no_advertise(ospf6, &p);
	if (ret == OSPF6_INVALID)
		vty_out(vty, "!!Invalid configuration\n");

	return CMD_SUCCESS;
}

DEFPY (no_ospf6_external_route_aggregation_no_advertise,
       no_ospf6_external_route_aggregation_no_advertise_cmd,
       "no summary-address X:X::X:X/M$prefix no-advertise",
       NO_STR
       "External summary address\n"
       "Specify IPv6 prefix\n"
       "Adverise summary route to the AS \n")
{
	VTY_DECLVAR_CONTEXT(ospf6, ospf6);

	struct prefix p;
	int ret = CMD_SUCCESS;

	ret = str2prefix(prefix_str, &p);
	if (ret == 0) {
		vty_out(vty, "Malformed prefix\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Apply mask for given prefix. */
	apply_mask(&p);

	if (!ospf6_is_valid_summary_addr(vty, &p))
		return CMD_WARNING_CONFIG_FAILED;

	ret = ospf6_asbr_external_rt_advertise(ospf6, &p);
	if (ret == OSPF6_INVALID)
		vty_out(vty, "!!Invalid configuration\n");

	return CMD_SUCCESS;
}

DEFPY (ospf6_route_aggregation_timer,
       ospf6_route_aggregation_timer_cmd,
       "aggregation timer (5-1800)",
       "External route aggregation\n"
       "Delay timer (in seconds)\n"
       "Timer interval(in seconds)\n")
{
	VTY_DECLVAR_CONTEXT(ospf6, ospf6);

	ospf6_external_aggr_delay_timer_set(ospf6, timer);

	return CMD_SUCCESS;
}

DEFPY (no_ospf6_route_aggregation_timer,
       no_ospf6_route_aggregation_timer_cmd,
       "no aggregation timer [5-1800]",
       NO_STR
       "External route aggregation\n"
       "Delay timer\n"
       "Timer interval(in seconds)\n")
{
	VTY_DECLVAR_CONTEXT(ospf6, ospf6);

	ospf6_external_aggr_delay_timer_set(ospf6,
			OSPF6_EXTL_AGGR_DEFAULT_DELAY);
	return CMD_SUCCESS;
}

static int
ospf6_print_vty_external_routes_walkcb(struct hash_bucket *bucket, void *arg)
{
	struct ospf6_route *rt = bucket->data;
	struct vty *vty = (struct vty *)arg;
	static unsigned int count;

	vty_out(vty, "%pFX ", &rt->prefix);

	count++;

	if (count%5 == 0)
		vty_out(vty, "\n");

	if (OSPF6_EXTERNAL_RT_COUNT(rt->aggr_route) == count)
		count = 0;

	return HASHWALK_CONTINUE;
}

static int
ospf6_print_json_external_routes_walkcb(struct hash_bucket *bucket, void *arg)
{
	struct ospf6_route *rt = bucket->data;
	struct json_object *json = (struct json_object *)arg;
	char buf[PREFIX2STR_BUFFER];
	char exnalbuf[20];
	static unsigned int count;

	prefix2str(&rt->prefix, buf, sizeof(buf));

	snprintf(exnalbuf, sizeof(exnalbuf), "Exnl Addr-%d", count);

	json_object_string_add(json, exnalbuf, buf);

	count++;

	if (OSPF6_EXTERNAL_RT_COUNT(rt->aggr_route) == count)
		count = 0;

	return HASHWALK_CONTINUE;
}

static void
ospf6_show_vrf_name(struct vty *vty, struct ospf6 *ospf6,
		    json_object *json)
{
	if (json) {
		if (ospf6->vrf_id == VRF_DEFAULT)
			json_object_string_add(json, "vrfName",
					       "default");
		else
			json_object_string_add(json, "vrfName",
					       ospf6->name);
		json_object_int_add(json, "vrfId", ospf6->vrf_id);
	} else {
		if (ospf6->vrf_id == VRF_DEFAULT)
			vty_out(vty, "VRF Name: %s\n", "default");
		else if (ospf6->name)
			vty_out(vty, "VRF Name: %s\n", ospf6->name);
	}
}

static int
ospf6_show_summary_address(struct vty *vty, struct ospf6 *ospf6,
			json_object *json,
			bool uj, const char *detail)
{
	struct route_node *rn;
	static const char header[] = "Summary-address       Metric-type     Metric     Tag         External_Rt_count\n";
	json_object *json_vrf = NULL;

	if (!uj) {
		ospf6_show_vrf_name(vty, ospf6, json_vrf);
		vty_out(vty, "aggregation delay interval: %u(in seconds)\n\n",
			ospf6->aggr_delay_interval);
		vty_out(vty, "%s\n", header);
	} else {
		json_vrf = json_object_new_object();

		ospf6_show_vrf_name(vty, ospf6, json_vrf);

		json_object_int_add(json_vrf, "aggregationDelayInterval",
				    ospf6->aggr_delay_interval);
	}


	for (rn = route_top(ospf6->rt_aggr_tbl); rn; rn = route_next(rn)) {
		if (!rn->info)
			continue;

		struct ospf6_external_aggr_rt *aggr = rn->info;
		json_object *json_aggr = NULL;
		char buf[PREFIX2STR_BUFFER];

		prefix2str(&aggr->p, buf, sizeof(buf));

		if (uj) {

			json_aggr = json_object_new_object();

			json_object_object_add(json_vrf,
						buf,
						json_aggr);

			json_object_string_add(json_aggr, "summaryAddress",
					       buf);

			json_object_string_add(
				json_aggr, "metricType",
				(aggr->mtype == DEFAULT_METRIC_TYPE) ? "E2"
								     : "E1");

			json_object_int_add(json_aggr, "Metric",
					   (aggr->metric != -1)
					    ? aggr->metric
					    : DEFAULT_DEFAULT_METRIC);

			json_object_int_add(json_aggr, "Tag",
					    aggr->tag);

			json_object_int_add(json_aggr, "externalRouteCount",
					    OSPF6_EXTERNAL_RT_COUNT(aggr));

			if (OSPF6_EXTERNAL_RT_COUNT(aggr) && detail) {
				json_object_int_add(json_aggr, "ID",
						    aggr->id);
				json_object_int_add(json_aggr, "Flags",
						    aggr->aggrflags);
				hash_walk(aggr->match_extnl_hash,
					ospf6_print_json_external_routes_walkcb,
							json_aggr);
			}

		} else {
			vty_out(vty, "%-22s", buf);

			(aggr->mtype == DEFAULT_METRIC_TYPE)
				? vty_out(vty, "%-16s", "E2")
				: vty_out(vty, "%-16s", "E1");
			vty_out(vty, "%-11d", (aggr->metric != -1)
					? aggr->metric
					: DEFAULT_DEFAULT_METRIC);

			vty_out(vty, "%-12u", aggr->tag);

			vty_out(vty, "%-5ld\n",
				OSPF6_EXTERNAL_RT_COUNT(aggr));

			if (OSPF6_EXTERNAL_RT_COUNT(aggr) && detail) {
				vty_out(vty,
					"Matched External routes:\n");
				hash_walk(aggr->match_extnl_hash,
				ospf6_print_vty_external_routes_walkcb,
							vty);
				vty_out(vty, "\n");
			}

			vty_out(vty, "\n");
		}
	}

	if (uj)
		json_object_object_add(json, ospf6->name,
					json_vrf);

	return CMD_SUCCESS;
}

DEFPY (show_ipv6_ospf6_external_aggregator,
       show_ipv6_ospf6_external_aggregator_cmd,
       "show ipv6 ospf6 [vrf <NAME|all>] summary-address [detail$detail] [json]",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       VRF_CMD_HELP_STR
       "All VRFs\n"
       "Show external summary addresses\n"
       "detailed information\n"
       JSON_STR)
{
	bool uj = use_json(argc, argv);
	struct ospf6 *ospf6 = NULL;
	json_object *json = NULL;
	const char *vrf_name = NULL;
	struct listnode *node;
	bool all_vrf = false;
	int idx_vrf = 0;

	if (uj)
		json = json_object_new_object();

	OSPF6_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);

	for (ALL_LIST_ELEMENTS_RO(om6->ospf6, node, ospf6)) {
		if (all_vrf || strcmp(ospf6->name, vrf_name) == 0) {

			ospf6_show_summary_address(vty, ospf6, json, uj,
						   detail);

			if (!all_vrf)
				break;
		}
	}

	if (uj) {
		vty_json(vty, json);
	}

	OSPF6_CMD_CHECK_VRF(uj, all_vrf, ospf6);

	return CMD_SUCCESS;
}

static void ospf6_stub_router_config_write(struct vty *vty, struct ospf6 *ospf6)
{
	if (CHECK_FLAG(ospf6->flag, OSPF6_STUB_ROUTER))
		vty_out(vty, " stub-router administrative\n");
	return;
}

static int ospf6_distance_config_write(struct vty *vty, struct ospf6 *ospf6)
{
	struct route_node *rn;
	struct ospf6_distance *odistance;

	if (ospf6->distance_all)
		vty_out(vty, " distance %u\n", ospf6->distance_all);

	if (ospf6->distance_intra || ospf6->distance_inter
	    || ospf6->distance_external) {
		vty_out(vty, " distance ospf6");

		if (ospf6->distance_intra)
			vty_out(vty, " intra-area %u", ospf6->distance_intra);
		if (ospf6->distance_inter)
			vty_out(vty, " inter-area %u", ospf6->distance_inter);
		if (ospf6->distance_external)
			vty_out(vty, " external %u", ospf6->distance_external);

		vty_out(vty, "\n");
	}

	for (rn = route_top(ospf6->distance_table); rn; rn = route_next(rn))
		if ((odistance = rn->info) != NULL)
			vty_out(vty, " distance %u %pFX %s\n",
				odistance->distance, &rn->p,
				odistance->access_list ? odistance->access_list
						       : "");
	return 0;
}

static int ospf6_asbr_summary_config_write(struct vty *vty, struct ospf6 *ospf6)
{
	struct route_node *rn;
	struct ospf6_external_aggr_rt *aggr;
	char buf[PREFIX2STR_BUFFER];

	if (ospf6->aggr_delay_interval != OSPF6_EXTL_AGGR_DEFAULT_DELAY)
		vty_out(vty, " aggregation timer %u\n",
				ospf6->aggr_delay_interval);

	/* print 'summary-address A:B::C:D/M' */
	for (rn = route_top(ospf6->rt_aggr_tbl); rn; rn = route_next(rn)) {
		if (!rn->info)
			continue;

		aggr = rn->info;

		prefix2str(&aggr->p, buf, sizeof(buf));
		vty_out(vty, " summary-address %s", buf);
		if (aggr->tag)
			vty_out(vty, " tag %u", aggr->tag);

		if (aggr->metric != -1)
			vty_out(vty, " metric %d", aggr->metric);

		if (aggr->mtype != DEFAULT_METRIC_TYPE)
			vty_out(vty, " metric-type %d", aggr->mtype);

		if (CHECK_FLAG(aggr->aggrflags,
			       OSPF6_EXTERNAL_AGGRT_NO_ADVERTISE))
			vty_out(vty, " no-advertise");

		vty_out(vty, "\n");
	}

	return 0;
}

/* OSPF configuration write function. */
static int config_write_ospf6(struct vty *vty)
{
	struct ospf6 *ospf6;
	struct listnode *node, *nnode;

	/* OSPFv3 configuration. */
	if (om6 == NULL)
		return CMD_SUCCESS;

	for (ALL_LIST_ELEMENTS(om6->ospf6, node, nnode, ospf6)) {
		if (ospf6->name && strcmp(ospf6->name, VRF_DEFAULT_NAME))
			vty_out(vty, "router ospf6 vrf %s\n", ospf6->name);
		else
			vty_out(vty, "router ospf6\n");

		if (ospf6->router_id_static != 0)
			vty_out(vty, " ospf6 router-id %pI4\n",
				&ospf6->router_id_static);

		if (CHECK_FLAG(ospf6->config_flags,
			       OSPF6_SEND_EXTRA_DATA_TO_ZEBRA))
			vty_out(vty, " ospf6 send-extra-data zebra\n");

		/* log-adjacency-changes flag print. */
		if (CHECK_FLAG(ospf6->config_flags,
			       OSPF6_LOG_ADJACENCY_CHANGES)) {
			if (CHECK_FLAG(ospf6->config_flags,
				       OSPF6_LOG_ADJACENCY_DETAIL))
				vty_out(vty, " log-adjacency-changes detail\n");
			else if (!SAVE_OSPF6_LOG_ADJACENCY_CHANGES)
				vty_out(vty, " log-adjacency-changes\n");
		} else if (SAVE_OSPF6_LOG_ADJACENCY_CHANGES) {
			vty_out(vty, " no log-adjacency-changes\n");
		}

		if (ospf6->ref_bandwidth != OSPF6_REFERENCE_BANDWIDTH)
			vty_out(vty, " auto-cost reference-bandwidth %d\n",
				ospf6->ref_bandwidth);

		if (ospf6->write_oi_count
		    != OSPF6_WRITE_INTERFACE_COUNT_DEFAULT)
			vty_out(vty, " write-multiplier %d\n",
				ospf6->write_oi_count);

		/* LSA timers print. */
		if (ospf6->lsa_minarrival != OSPF_MIN_LS_ARRIVAL)
			vty_out(vty, " timers lsa min-arrival %d\n",
				ospf6->lsa_minarrival);

		/* ECMP max path config */
		if (ospf6->max_multipath != MULTIPATH_NUM)
			vty_out(vty, " maximum-paths %d\n",
				ospf6->max_multipath);

		ospf6_stub_router_config_write(vty, ospf6);
		ospf6_redistribute_config_write(vty, ospf6);
		ospf6_area_config_write(vty, ospf6);
		ospf6_spf_config_write(vty, ospf6);
		ospf6_distance_config_write(vty, ospf6);
		ospf6_distribute_config_write(vty, ospf6);
		ospf6_asbr_summary_config_write(vty, ospf6);
		config_write_ospf6_gr(vty, ospf6);
		config_write_ospf6_gr_helper(vty, ospf6);

		vty_out(vty, "exit\n");
		vty_out(vty, "!\n");
	}
	return 0;
}

static int config_write_ospf6(struct vty *vty);
/* OSPF6 node structure. */
static struct cmd_node ospf6_node = {
	.name = "ospf6",
	.node = OSPF6_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(config-ospf6)# ",
	.config_write = config_write_ospf6,
};

void install_element_ospf6_clear_process(void)
{
	install_element(ENABLE_NODE, &clear_router_ospf6_cmd);
}

/* Install ospf related commands. */
void ospf6_top_init(void)
{
	/* Install ospf6 top node. */
	install_node(&ospf6_node);

	install_element(VIEW_NODE, &show_ipv6_ospf6_cmd);
	install_element(VIEW_NODE, &show_ipv6_ospf6_vrfs_cmd);
	install_element(CONFIG_NODE, &router_ospf6_cmd);
	install_element(CONFIG_NODE, &no_router_ospf6_cmd);

	install_element(VIEW_NODE, &show_ipv6_ospf6_route_cmd);
	install_element(VIEW_NODE, &show_ipv6_ospf6_route_match_cmd);
	install_element(VIEW_NODE, &show_ipv6_ospf6_route_match_detail_cmd);
	install_element(VIEW_NODE, &show_ipv6_ospf6_route_type_detail_cmd);

	install_default(OSPF6_NODE);
	install_element(OSPF6_NODE, &ospf6_router_id_cmd);
	install_element(OSPF6_NODE, &no_ospf6_router_id_cmd);
	install_element(OSPF6_NODE, &ospf6_log_adjacency_changes_cmd);
	install_element(OSPF6_NODE, &ospf6_log_adjacency_changes_detail_cmd);
	install_element(OSPF6_NODE, &no_ospf6_log_adjacency_changes_cmd);
	install_element(OSPF6_NODE, &no_ospf6_log_adjacency_changes_detail_cmd);
	install_element(OSPF6_NODE, &ospf6_send_extra_data_cmd);

	/* LSA timers commands */
	install_element(OSPF6_NODE, &ospf6_timers_lsa_cmd);
	install_element(OSPF6_NODE, &no_ospf6_timers_lsa_cmd);

	install_element(OSPF6_NODE, &ospf6_interface_area_cmd);
	install_element(OSPF6_NODE, &no_ospf6_interface_area_cmd);
	install_element(OSPF6_NODE, &ospf6_stub_router_admin_cmd);
	install_element(OSPF6_NODE, &no_ospf6_stub_router_admin_cmd);

	/* maximum-paths command */
	install_element(OSPF6_NODE, &ospf6_max_multipath_cmd);
	install_element(OSPF6_NODE, &no_ospf6_max_multipath_cmd);

	/* ASBR Summarisation */
	install_element(OSPF6_NODE, &ospf6_external_route_aggregation_cmd);
	install_element(OSPF6_NODE, &no_ospf6_external_route_aggregation_cmd);
	install_element(OSPF6_NODE,
		&ospf6_external_route_aggregation_no_advertise_cmd);
	install_element(OSPF6_NODE,
			&no_ospf6_external_route_aggregation_no_advertise_cmd);
	install_element(OSPF6_NODE, &ospf6_route_aggregation_timer_cmd);
	install_element(OSPF6_NODE, &no_ospf6_route_aggregation_timer_cmd);
	install_element(VIEW_NODE, &show_ipv6_ospf6_external_aggregator_cmd);

	install_element(OSPF6_NODE, &ospf6_distance_cmd);
	install_element(OSPF6_NODE, &no_ospf6_distance_cmd);
	install_element(OSPF6_NODE, &ospf6_distance_ospf6_cmd);
	install_element(OSPF6_NODE, &no_ospf6_distance_ospf6_cmd);
}
