// SPDX-License-Identifier: GPL-2.0-or-later
/* OSPF version 2 daemon program.
 * Copyright (C) 1999, 2000 Toshiaki Takada
 */

#include <zebra.h>

#include "frrevent.h"
#include "vty.h"
#include "command.h"
#include "linklist.h"
#include "prefix.h"
#include "table.h"
#include "if.h"
#include "memory.h"
#include "stream.h"
#include "log.h"
#include "sockunion.h" /* for inet_aton () */
#include "zclient.h"
#include "routemap.h"
#include "plist.h"
#include "sockopt.h"
#include "bfd.h"
#include "libfrr.h"
#include "defaults.h"
#include "lib_errors.h"
#include "ldp_sync.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_bfd.h"
#include "ospfd/ospf_network.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_packet.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_route.h"
#include "ospfd/ospf_zebra.h"
#include "ospfd/ospf_abr.h"
#include "ospfd/ospf_flood.h"
#include "ospfd/ospf_ase.h"
#include "ospfd/ospf_ldp_sync.h"
#include "ospfd/ospf_gr.h"
#include "ospfd/ospf_apiserver.h"


DEFINE_QOBJ_TYPE(ospf);

/* OSPF process wide configuration. */
static struct ospf_master ospf_master;

/* OSPF process wide configuration pointer to export. */
struct ospf_master *om;

unsigned short ospf_instance;

extern struct zclient *zclient;
extern struct zclient *zclient_sync;

/* OSPF config processing timer thread */
struct event *t_ospf_cfg;

static void ospf_remove_vls_through_area(struct ospf *, struct ospf_area *);
static void ospf_network_free(struct ospf *, struct ospf_network *);
static void ospf_area_free(struct ospf_area *);
static void ospf_network_run(struct prefix *, struct ospf_area *);
static void ospf_network_run_interface(struct ospf *, struct interface *,
				       struct prefix *, struct ospf_area *);
static void ospf_network_run_subnet(struct ospf *, struct connected *,
				    struct prefix *, struct ospf_area *);
static int ospf_network_match_iface(const struct connected *,
				    const struct prefix *);
static void ospf_finish_final(struct ospf *);

/* API to clean refresh queues and LSAs */
static void ospf_free_refresh_queue(struct ospf *ospf)
{
	for (int i = 0; i < OSPF_LSA_REFRESHER_SLOTS; i++) {
		struct list *list = ospf->lsa_refresh_queue.qs[i];
		struct listnode *node, *nnode;
		struct ospf_lsa *lsa;

		if (list) {
			for (ALL_LIST_ELEMENTS(list, node, nnode, lsa)) {
				listnode_delete(list, lsa);
				lsa->refresh_list = -1;
				ospf_lsa_unlock(&lsa);
			}
			list_delete(&list);
			ospf->lsa_refresh_queue.qs[i] = NULL;
		}
	}
}
#define OSPF_EXTERNAL_LSA_ORIGINATE_DELAY 1

int p_spaces_compare_func(const struct p_space *a, const struct p_space *b)
{
	if (a->protected_resource->type == OSPF_TI_LFA_LINK_PROTECTION
	    && b->protected_resource->type == OSPF_TI_LFA_LINK_PROTECTION)
		return (a->protected_resource->link->link_id.s_addr
			- b->protected_resource->link->link_id.s_addr);

	if (a->protected_resource->type == OSPF_TI_LFA_NODE_PROTECTION
	    && b->protected_resource->type == OSPF_TI_LFA_NODE_PROTECTION)
		return (a->protected_resource->router_id.s_addr
			- b->protected_resource->router_id.s_addr);

	/* This should not happen */
	return 0;
}

int q_spaces_compare_func(const struct q_space *a, const struct q_space *b)
{
	return (a->root->id.s_addr - b->root->id.s_addr);
}

DECLARE_RBTREE_UNIQ(p_spaces, struct p_space, p_spaces_item,
		    p_spaces_compare_func);

void ospf_process_refresh_data(struct ospf *ospf, bool reset)
{
	struct vrf *vrf = vrf_lookup_by_id(ospf->vrf_id);
	struct in_addr router_id, router_id_old;
	struct ospf_interface *oi;
	struct interface *ifp;
	struct listnode *node, *nnode;
	struct ospf_area *area;
	bool rid_change = false;

	if (!ospf->oi_running) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug(
				"Router ospf not configured -- Router-ID update postponed");
		return;
	}

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("Router-ID[OLD:%pI4]: Update",
			   &ospf->router_id);

	router_id_old = ospf->router_id;

	/* Select the router ID based on these priorities:
	     1. Statically assigned router ID is always the first choice.
	     2. Just go with whatever the zebra daemon recommends.
	*/
	if (ospf->router_id_static.s_addr != INADDR_ANY)
		router_id = ospf->router_id_static;
	else
		router_id = ospf->router_id_zebra;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("Router-ID[OLD:%pI4]: Update to %pI4",
			   &ospf->router_id, &router_id);

	rid_change = !(IPV4_ADDR_SAME(&router_id_old, &router_id));
	if (rid_change || (reset)) {
		for (ALL_LIST_ELEMENTS_RO(ospf->oiflist, node, oi)) {
			/* Some nbrs are identified by router_id, these needs
			 * to be rebuilt. Possible optimization would be to do
			 * oi->nbr_self->router_id = router_id for
			 * !(virtual | ptop) links
			 */
			ospf_nbr_self_reset(oi, router_id);

			/*
			 * If the old router id was not set, but now it
			 * is and the interface is operative and the
			 * state is ISM_Down we should kick the state
			 * machine as that we processed the interfaces
			 * based upon the network statement( or intf config )
			 * but could not start it at that time.
			 */
			if (if_is_operative(oi->ifp) && oi->state == ISM_Down
			    && router_id_old.s_addr == INADDR_ANY)
				ospf_if_up(oi);
		}

		/* Flush (inline) all the self originated LSAs */
		ospf_flush_self_originated_lsas_now(ospf);

		ospf->router_id = router_id;
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("Router-ID[NEW:%pI4]: Update",
				   &ospf->router_id);

		/* Flush (inline) all external LSAs which now match the new
		   router-id,
		   need to adjust the OSPF_LSA_SELF flag, so the flush doesn't
		   hit
		   asserts in ospf_refresher_unregister_lsa(). This step is
		   needed
		   because the current frr code does look-up for
		   self-originated LSAs
		   based on the self router-id alone but expects OSPF_LSA_SELF
		   to be
		   properly set */
		if (ospf->lsdb) {
			struct route_node *rn;
			struct ospf_lsa *lsa;

			LSDB_LOOP (EXTERNAL_LSDB(ospf), rn, lsa) {
				/* AdvRouter and Router ID is the same. */
				if (IPV4_ADDR_SAME(&lsa->data->adv_router,
					&ospf->router_id) && rid_change) {
					SET_FLAG(lsa->flags,
						 OSPF_LSA_SELF_CHECKED);
					SET_FLAG(lsa->flags, OSPF_LSA_SELF);
					ospf_lsa_flush_schedule(ospf, lsa);
				}
				/* The above flush will send immediately
				 * So discard the LSA to originate new
				 */
				ospf_discard_from_db(ospf, ospf->lsdb, lsa);
			}

			LSDB_LOOP (OPAQUE_AS_LSDB(ospf), rn, lsa)
				ospf_discard_from_db(ospf, ospf->lsdb, lsa);

			ospf_lsdb_delete_all(ospf->lsdb);
		}

		/* Since the LSAs are deleted, need reset the aggr flag */
		ospf_unset_all_aggr_flag(ospf);

		/* Delete the LSDB */
		for (ALL_LIST_ELEMENTS(ospf->areas, node, nnode, area))
			ospf_area_lsdb_discard_delete(area);

		/* update router-lsa's for each area */
		ospf_router_lsa_update(ospf);

		/* update ospf_interface's */
		FOR_ALL_INTERFACES (vrf, ifp) {
			if (reset)
				ospf_if_reset(ifp);
			else
				ospf_if_update(ospf, ifp);
		}

		ospf_external_lsa_rid_change(ospf);

#ifdef SUPPORT_OSPF_API
		ospf_apiserver_clients_notify_router_id_change(router_id);
#endif
	}

	ospf->inst_shutdown = 0;
}

void ospf_router_id_update(struct ospf *ospf)
{
	ospf_process_refresh_data(ospf, false);
}

void ospf_process_reset(struct ospf *ospf)
{
	ospf_process_refresh_data(ospf, true);
}

void ospf_neighbor_reset(struct ospf *ospf, struct in_addr nbr_id,
			const char *nbr_str)
{
	struct route_node *rn;
	struct ospf_neighbor *nbr;
	struct ospf_interface *oi;
	struct listnode *node;

	/* Clear only a particular nbr with nbr router id as nbr_id */
	if (nbr_str != NULL) {
		for (ALL_LIST_ELEMENTS_RO(ospf->oiflist, node, oi)) {
			nbr = ospf_nbr_lookup_by_routerid(oi->nbrs, &nbr_id);
			if (nbr)
				OSPF_NSM_EVENT_EXECUTE(nbr, NSM_KillNbr);
		}
		return;
	}

	/* send Neighbor event KillNbr to all associated neighbors. */
	for (ALL_LIST_ELEMENTS_RO(ospf->oiflist, node, oi)) {
		for (rn = route_top(oi->nbrs); rn; rn = route_next(rn)) {
			nbr = rn->info;
			if (nbr && (nbr != oi->nbr_self))
				OSPF_NSM_EVENT_EXECUTE(nbr, NSM_KillNbr);
		}
	}
}

/* For OSPF area sort by area id. */
static int ospf_area_id_cmp(struct ospf_area *a1, struct ospf_area *a2)
{
	if (ntohl(a1->area_id.s_addr) > ntohl(a2->area_id.s_addr))
		return 1;
	if (ntohl(a1->area_id.s_addr) < ntohl(a2->area_id.s_addr))
		return -1;
	return 0;
}

static void ospf_add(struct ospf *ospf)
{
	listnode_add(om->ospf, ospf);
}

static void ospf_delete(struct ospf *ospf)
{
	listnode_delete(om->ospf, ospf);
}

struct ospf *ospf_new_alloc(unsigned short instance, const char *name)
{
	int i;
	struct vrf *vrf = NULL;

	struct ospf *new = XCALLOC(MTYPE_OSPF_TOP, sizeof(struct ospf));

	new->instance = instance;
	new->router_id.s_addr = htonl(0);
	new->router_id_static.s_addr = htonl(0);

	vrf = vrf_lookup_by_name(name);
	if (vrf)
		new->vrf_id = vrf->vrf_id;
	else
		new->vrf_id = VRF_UNKNOWN;

	/* Freed in ospf_finish_final */
	new->name = XSTRDUP(MTYPE_OSPF_TOP, name);
	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug(
			"%s: Create new ospf instance with vrf_name %s vrf_id %u",
			__func__, name, new->vrf_id);

	if (vrf)
		ospf_vrf_link(new, vrf);

	ospf_zebra_vrf_register(new);

	new->abr_type = OSPF_ABR_DEFAULT;
	new->oiflist = list_new();
	new->vlinks = list_new();
	new->areas = list_new();
	new->areas->cmp = (int (*)(void *, void *))ospf_area_id_cmp;
	new->networks = route_table_init();
	new->nbr_nbma = route_table_init();

	new->lsdb = ospf_lsdb_new();

	new->default_originate = DEFAULT_ORIGINATE_NONE;

	new->passive_interface_default = OSPF_IF_ACTIVE;

	new->new_external_route = route_table_init();
	new->old_external_route = route_table_init();
	new->external_lsas = route_table_init();

	new->stub_router_startup_time = OSPF_STUB_ROUTER_UNCONFIGURED;
	new->stub_router_shutdown_time = OSPF_STUB_ROUTER_UNCONFIGURED;
	new->stub_router_admin_set = OSPF_STUB_ROUTER_ADMINISTRATIVE_UNSET;

	/* Distribute parameter init. */
	for (i = 0; i <= ZEBRA_ROUTE_MAX; i++) {
		new->dtag[i] = 0;
	}
	new->default_metric = -1;
	new->ref_bandwidth = OSPF_DEFAULT_REF_BANDWIDTH;

	/* LSA timers */
	new->min_ls_interval = OSPF_MIN_LS_INTERVAL;
	new->min_ls_arrival = OSPF_MIN_LS_ARRIVAL;

	/* SPF timer value init. */
	new->spf_delay = OSPF_SPF_DELAY_DEFAULT;
	new->spf_holdtime = OSPF_SPF_HOLDTIME_DEFAULT;
	new->spf_max_holdtime = OSPF_SPF_MAX_HOLDTIME_DEFAULT;
	new->spf_hold_multiplier = 1;

	/* MaxAge init. */
	new->maxage_delay = OSPF_LSA_MAXAGE_REMOVE_DELAY_DEFAULT;
	new->maxage_lsa = route_table_init();
	new->t_maxage_walker = NULL;
	event_add_timer(master, ospf_lsa_maxage_walker, new,
			OSPF_LSA_MAXAGE_CHECK_INTERVAL, &new->t_maxage_walker);

	/* Max paths initialization */
	new->max_multipath = MULTIPATH_NUM;

	/* Distance table init. */
	new->distance_table = route_table_init();

	new->lsa_refresh_queue.index = 0;
	new->lsa_refresh_interval = OSPF_LSA_REFRESH_INTERVAL_DEFAULT;
	new->lsa_refresh_timer = OSPF_LS_REFRESH_TIME;
	new->t_lsa_refresher = NULL;
	event_add_timer(master, ospf_lsa_refresh_walker, new,
			new->lsa_refresh_interval, &new->t_lsa_refresher);
	new->lsa_refresher_started = monotime(NULL);

	new->ibuf = stream_new(OSPF_MAX_PACKET_SIZE + 1);

	new->t_read = NULL;
	new->oi_write_q = list_new();
	new->write_oi_count = OSPF_WRITE_INTERFACE_COUNT_DEFAULT;

	new->proactive_arp = OSPF_PROACTIVE_ARP_DEFAULT;

	ospf_gr_helper_instance_init(new);

	ospf_asbr_external_aggregator_init(new);

	ospf_opaque_type11_lsa_init(new);

	QOBJ_REG(new, ospf);

	new->fd = -1;
	new->intf_socket_enabled = true;

	new->recv_sock_bufsize = OSPF_DEFAULT_SOCK_BUFSIZE;
	new->send_sock_bufsize = OSPF_DEFAULT_SOCK_BUFSIZE;

	return new;
}

/* Allocate new ospf structure. */
static struct ospf *ospf_new(unsigned short instance, const char *name)
{
	struct ospf *new;

	new = ospf_new_alloc(instance, name);
	ospf_add(new);

	if (new->vrf_id == VRF_UNKNOWN)
		return new;

	if ((ospf_sock_init(new)) < 0) {
		flog_err(EC_LIB_SOCKET,
			 "%s: ospf_sock_init is unable to open a socket",
			 __func__);
		return new;
	}

	event_add_read(master, ospf_read, new, new->fd, &new->t_read);

	new->oi_running = 1;
	ospf_router_id_update(new);

	/*
	 * Read from non-volatile memory whether this instance is performing a
	 * graceful restart or not.
	 */
	ospf_gr_nvm_read(new);

	new->fr_configured = false;

	return new;
}

struct ospf *ospf_lookup_instance(unsigned short instance)
{
	struct ospf *ospf;
	struct listnode *node, *nnode;

	if (listcount(om->ospf) == 0)
		return NULL;

	for (ALL_LIST_ELEMENTS(om->ospf, node, nnode, ospf))
		if ((ospf->instance == 0 && instance == 0)
		    || (ospf->instance && instance
			&& ospf->instance == instance))
			return ospf;

	return NULL;
}

static int ospf_is_ready(struct ospf *ospf)
{
	/* OSPF must be on and Router-ID must be configured. */
	if (!ospf || ospf->router_id.s_addr == INADDR_ANY)
		return 0;

	return 1;
}

struct ospf *ospf_lookup_by_inst_name(unsigned short instance, const char *name)
{
	struct ospf *ospf = NULL;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(om->ospf, node, nnode, ospf)) {
		if ((ospf->instance == instance)
		    && ((ospf->name == NULL && name == NULL)
			|| (ospf->name && name
			    && strcmp(ospf->name, name) == 0)))
			return ospf;
	}
	return NULL;
}

struct ospf *ospf_lookup(unsigned short instance, const char *name)
{
	struct ospf *ospf;

	if (ospf_instance) {
		ospf = ospf_lookup_instance(instance);
	} else {
		ospf = ospf_lookup_by_inst_name(instance, name);
	}

	return ospf;
}

struct ospf *ospf_get(unsigned short instance, const char *name, bool *created)
{
	struct ospf *ospf;

	ospf = ospf_lookup(instance, name);

	*created = (ospf == NULL);
	if (ospf == NULL)
		ospf = ospf_new(instance, name);

	return ospf;
}

struct ospf *ospf_lookup_by_vrf_id(vrf_id_t vrf_id)
{
	struct vrf *vrf = NULL;

	vrf = vrf_lookup_by_id(vrf_id);
	if (!vrf)
		return NULL;
	return (vrf->info) ? (struct ospf *)vrf->info : NULL;
}

uint32_t ospf_count_area_params(struct ospf *ospf)
{
	struct vrf *vrf;
	struct interface *ifp;
	uint32_t count = 0;

	if (ospf->vrf_id != VRF_UNKNOWN) {
		vrf = vrf_lookup_by_id(ospf->vrf_id);

		FOR_ALL_INTERFACES (vrf, ifp) {
			count += ospf_if_count_area_params(ifp);
		}
	}

	return count;
}

/* It should only be used when processing incoming info update from zebra.
 * Other situations, it is not sufficient to lookup the ospf instance by
 * vrf_name only without using the instance number.
 */
static struct ospf *ospf_lookup_by_name(const char *vrf_name)
{
	struct ospf *ospf = NULL;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(om->ospf, node, nnode, ospf))
		if ((ospf->name == NULL && vrf_name == NULL)
		    || (ospf->name && vrf_name
			&& strcmp(ospf->name, vrf_name) == 0))
			return ospf;
	return NULL;
}

/* Timer thread for deferred shutdown */
static void ospf_deferred_shutdown_timer(struct event *t)
{
	struct ospf *ospf = EVENT_ARG(t);

	ospf_finish_final(ospf);
}

/* Check whether deferred-shutdown must be scheduled, otherwise call
 * down directly into second-half of instance shutdown.
 */
static void ospf_deferred_shutdown_check(struct ospf *ospf)
{
	unsigned long timeout;
	struct listnode *ln;
	struct ospf_area *area;

	/* deferred shutdown already running? */
	if (ospf->t_deferred_shutdown)
		return;

	/* Should we try push out max-metric LSAs? */
	if (ospf->stub_router_shutdown_time != OSPF_STUB_ROUTER_UNCONFIGURED) {
		for (ALL_LIST_ELEMENTS_RO(ospf->areas, ln, area)) {
			SET_FLAG(area->stub_router_state,
				 OSPF_AREA_ADMIN_STUB_ROUTED);

			if (!CHECK_FLAG(area->stub_router_state,
					OSPF_AREA_IS_STUB_ROUTED))
				ospf_router_lsa_update_area(area);
		}
		timeout = ospf->stub_router_shutdown_time;
		OSPF_TIMER_ON(ospf->t_deferred_shutdown,
			      ospf_deferred_shutdown_timer, timeout);
	} else {
		/* No timer needed */
		ospf_finish_final(ospf);
	}
}

/* Shut down the entire process */
void ospf_terminate(void)
{
	struct ospf *ospf;
	struct listnode *node, *nnode;

	/* shutdown already in progress */
	if (CHECK_FLAG(om->options, OSPF_MASTER_SHUTDOWN))
		return;

	SET_FLAG(om->options, OSPF_MASTER_SHUTDOWN);

	for (ALL_LIST_ELEMENTS(om->ospf, node, nnode, ospf))
		ospf_finish(ospf);

	/* Cleanup GR */
	ospf_gr_helper_stop();

	/* Cleanup route maps */
	route_map_finish();

	/* reverse prefix_list_init */
	prefix_list_add_hook(NULL);
	prefix_list_delete_hook(NULL);
	prefix_list_reset();

	/* Cleanup vrf info */
	ospf_vrf_terminate();

	keychain_terminate();

	ospf_opaque_term();
	list_delete(&om->ospf);

	/* Deliberately go back up, hopefully to thread scheduler, as
	 * One or more ospf_finish()'s may have deferred shutdown to a timer
	 * thread
	 */
	zclient_stop(zclient);
	zclient_free(zclient);
	zclient_stop(zclient_sync);
	zclient_free(zclient_sync);

	frr_fini();
}

void ospf_finish(struct ospf *ospf)
{
	if (CHECK_FLAG(om->options, OSPF_MASTER_SHUTDOWN))
		ospf_finish_final(ospf);
	else {
		/* let deferred shutdown decide */
		ospf_deferred_shutdown_check(ospf);
	}
}

/* Final cleanup of ospf instance */
static void ospf_finish_final(struct ospf *ospf)
{
	struct vrf *vrf = vrf_lookup_by_id(ospf->vrf_id);
	struct route_node *rn;
	struct ospf_nbr_nbma *nbr_nbma;
	struct ospf_lsa *lsa;
	struct ospf_interface *oi;
	struct ospf_area *area;
	struct ospf_vl_data *vl_data;
	struct listnode *node, *nnode;
	struct ospf_redist *red;
	int i;

	QOBJ_UNREG(ospf);

	ospf_opaque_type11_lsa_term(ospf);

	ospf_opaque_finish();

	if (!ospf->gr_info.prepare_in_progress)
		ospf_flush_self_originated_lsas_now(ospf);
	XFREE(MTYPE_TMP, ospf->gr_info.exit_reason);

	/* Unregister redistribution */
	for (i = 0; i < ZEBRA_ROUTE_MAX; i++) {
		struct list *red_list;

		red_list = ospf->redist[i];
		if (!red_list)
			continue;

		for (ALL_LIST_ELEMENTS(red_list, node, nnode, red)) {
			ospf_redistribute_unset(ospf, i, red->instance);
			ospf_redist_del(ospf, i, red->instance);
		}
	}
	red = ospf_redist_lookup(ospf, DEFAULT_ROUTE, 0);
	if (red) {
		ospf_routemap_unset(red);
		ospf_redist_del(ospf, DEFAULT_ROUTE, 0);
		ospf_redistribute_default_set(ospf, DEFAULT_ORIGINATE_NONE, 0, 0);
	}

	for (ALL_LIST_ELEMENTS(ospf->areas, node, nnode, area))
		ospf_remove_vls_through_area(ospf, area);

	for (ALL_LIST_ELEMENTS(ospf->vlinks, node, nnode, vl_data))
		ospf_vl_delete(ospf, vl_data);

	list_delete(&ospf->vlinks);

	/* shutdown LDP-Sync */
	if (ospf->vrf_id == VRF_DEFAULT)
		ospf_ldp_sync_gbl_exit(ospf, true);

	/* Reset interface. */
	for (ALL_LIST_ELEMENTS(ospf->oiflist, node, nnode, oi))
		ospf_if_free(oi);
	list_delete(&ospf->oiflist);
	ospf->oi_running = 0;

	/* De-Register VRF */
	ospf_zebra_vrf_deregister(ospf);

	/* Clear static neighbors */
	for (rn = route_top(ospf->nbr_nbma); rn; rn = route_next(rn))
		if ((nbr_nbma = rn->info)) {
			EVENT_OFF(nbr_nbma->t_poll);

			if (nbr_nbma->nbr) {
				nbr_nbma->nbr->nbr_nbma = NULL;
				nbr_nbma->nbr = NULL;
			}

			if (nbr_nbma->oi) {
				listnode_delete(nbr_nbma->oi->nbr_nbma,
						nbr_nbma);
				nbr_nbma->oi = NULL;
			}

			XFREE(MTYPE_OSPF_NEIGHBOR_STATIC, nbr_nbma);
		}

	route_table_finish(ospf->nbr_nbma);

	/* Clear networks and Areas. */
	for (rn = route_top(ospf->networks); rn; rn = route_next(rn)) {
		struct ospf_network *network;

		if ((network = rn->info) != NULL) {
			ospf_network_free(ospf, network);
			rn->info = NULL;
			route_unlock_node(rn);
		}
	}
	route_table_finish(ospf->networks);

	for (ALL_LIST_ELEMENTS(ospf->areas, node, nnode, area)) {
		listnode_delete(ospf->areas, area);
		ospf_area_free(area);
	}

	LSDB_LOOP (OPAQUE_AS_LSDB(ospf), rn, lsa)
		ospf_discard_from_db(ospf, ospf->lsdb, lsa);
	LSDB_LOOP (EXTERNAL_LSDB(ospf), rn, lsa)
		ospf_discard_from_db(ospf, ospf->lsdb, lsa);

	ospf_lsdb_delete_all(ospf->lsdb);
	ospf_lsdb_free(ospf->lsdb);

	for (rn = route_top(ospf->maxage_lsa); rn; rn = route_next(rn)) {
		if ((lsa = rn->info) != NULL) {
			ospf_lsa_unlock(&lsa);
			rn->info = NULL;
			route_unlock_node(rn);
		}
	}
	route_table_finish(ospf->maxage_lsa);

	if (ospf->old_table)
		ospf_route_table_free(ospf->old_table);
	if (ospf->new_table) {
		if (!ospf->gr_info.prepare_in_progress)
			ospf_route_delete(ospf, ospf->new_table);
		ospf_route_table_free(ospf->new_table);
	}
	if (ospf->oall_rtrs)
		ospf_rtrs_free(ospf->oall_rtrs);
	if (ospf->all_rtrs)
		ospf_rtrs_free(ospf->all_rtrs);
	if (ospf->old_rtrs)
		ospf_rtrs_free(ospf->old_rtrs);
	if (ospf->new_rtrs)
		ospf_rtrs_free(ospf->new_rtrs);
	if (ospf->new_external_route) {
		if (!ospf->gr_info.prepare_in_progress)
			ospf_route_delete(ospf, ospf->new_external_route);
		ospf_route_table_free(ospf->new_external_route);
	}
	if (ospf->old_external_route) {
		if (!ospf->gr_info.prepare_in_progress)
			ospf_route_delete(ospf, ospf->old_external_route);
		ospf_route_table_free(ospf->old_external_route);
	}
	if (ospf->external_lsas) {
		ospf_ase_external_lsas_finish(ospf->external_lsas);
	}

	for (i = ZEBRA_ROUTE_SYSTEM; i <= ZEBRA_ROUTE_MAX; i++) {
		struct list *ext_list;
		struct ospf_external *ext;

		ext_list = ospf->external[i];
		if (!ext_list)
			continue;

		for (ALL_LIST_ELEMENTS(ext_list, node, nnode, ext)) {
			if (ext->external_info)
				for (rn = route_top(ext->external_info); rn;
				     rn = route_next(rn)) {
					if (rn->info == NULL)
						continue;

					XFREE(MTYPE_OSPF_EXTERNAL_INFO,
					      rn->info);
					rn->info = NULL;
					route_unlock_node(rn);
				}

			ospf_external_del(ospf, i, ext->instance);
		}
	}

	ospf_distance_reset(ospf);
	route_table_finish(ospf->distance_table);

	/* Release extrenal Aggregator table */
	for (rn = route_top(ospf->rt_aggr_tbl); rn; rn = route_next(rn)) {
		struct ospf_external_aggr_rt *aggr;

		aggr = rn->info;

		if (aggr) {
			ospf_external_aggregator_free(aggr);
			rn->info = NULL;
			route_unlock_node(rn);
		}
	}

	/* Cancel all timers. */
	EVENT_OFF(ospf->t_read);
	EVENT_OFF(ospf->t_write);
	EVENT_OFF(ospf->t_spf_calc);
	EVENT_OFF(ospf->t_ase_calc);
	EVENT_OFF(ospf->t_maxage);
	EVENT_OFF(ospf->t_maxage_walker);
	EVENT_OFF(ospf->t_deferred_shutdown);
	EVENT_OFF(ospf->t_abr_task);
	EVENT_OFF(ospf->t_abr_fr);
	EVENT_OFF(ospf->t_asbr_check);
	EVENT_OFF(ospf->t_asbr_redist_update);
	EVENT_OFF(ospf->t_distribute_update);
	EVENT_OFF(ospf->t_lsa_refresher);
	EVENT_OFF(ospf->t_opaque_lsa_self);
	EVENT_OFF(ospf->t_sr_update);
	EVENT_OFF(ospf->t_default_routemap_timer);
	EVENT_OFF(ospf->t_external_aggr);
	EVENT_OFF(ospf->gr_info.t_grace_period);

	route_table_finish(ospf->rt_aggr_tbl);

	ospf_free_refresh_queue(ospf);

	list_delete(&ospf->areas);
	list_delete(&ospf->oi_write_q);

	/* Reset GR helper data structers */
	ospf_gr_helper_instance_stop(ospf);

	close(ospf->fd);
	stream_free(ospf->ibuf);
	ospf->fd = -1;
	ospf->max_multipath = MULTIPATH_NUM;
	ospf_delete(ospf);

	if (vrf)
		ospf_vrf_unlink(ospf, vrf);

	XFREE(MTYPE_OSPF_TOP, ospf->name);
	XFREE(MTYPE_OSPF_TOP, ospf);
}

static void ospf_range_table_node_destroy(route_table_delegate_t *delegate,
			struct route_table *table, struct route_node *node)
{
	XFREE(MTYPE_OSPF_AREA_RANGE, node->info);
	XFREE(MTYPE_ROUTE_NODE, node);
}

route_table_delegate_t ospf_range_table_delegate = {.create_node = route_node_create,
						 .destroy_node = ospf_range_table_node_destroy};

/* allocate new OSPF Area object */
struct ospf_area *ospf_area_new(struct ospf *ospf, struct in_addr area_id)
{
	struct ospf_area *new;

	/* Allocate new config_network. */
	new = XCALLOC(MTYPE_OSPF_AREA, sizeof(struct ospf_area));

	new->ospf = ospf;

	new->area_id = area_id;
	new->area_id_fmt = OSPF_AREA_ID_FMT_DOTTEDQUAD;

	new->external_routing = OSPF_AREA_DEFAULT;
	new->default_cost = 1;
	new->auth_type = OSPF_AUTH_NULL;

	/* New LSDB init. */
	new->lsdb = ospf_lsdb_new();

	/* Self-originated LSAs initialize. */
	new->router_lsa_self = NULL;

	/* Initialize FR field */
	new->fr_info.enabled = false;
	new->fr_info.configured = false;
	new->fr_info.state_changed = false;
	new->fr_info.router_lsas_recv_dc_bit = 0;
	new->fr_info.indication_lsa_self = NULL;
	new->fr_info.area_ind_lsa_recvd = false;
	new->fr_info.area_dc_clear = false;

	ospf_opaque_type10_lsa_init(new);

	new->oiflist = list_new();
	new->ranges = route_table_init_with_delegate(&ospf_range_table_delegate);
	new->nssa_ranges = route_table_init_with_delegate(&ospf_range_table_delegate);

	if (area_id.s_addr == OSPF_AREA_BACKBONE)
		ospf->backbone = new;

	return new;
}

void ospf_area_lsdb_discard_delete(struct ospf_area *area)
{
	struct route_node *rn;
	struct ospf_lsa *lsa;

	LSDB_LOOP (ROUTER_LSDB(area), rn, lsa)
		ospf_discard_from_db(area->ospf, area->lsdb, lsa);
	LSDB_LOOP (NETWORK_LSDB(area), rn, lsa)
		ospf_discard_from_db(area->ospf, area->lsdb, lsa);
	LSDB_LOOP (SUMMARY_LSDB(area), rn, lsa)
		ospf_discard_from_db(area->ospf, area->lsdb, lsa);
	LSDB_LOOP (ASBR_SUMMARY_LSDB(area), rn, lsa)
		ospf_discard_from_db(area->ospf, area->lsdb, lsa);

	LSDB_LOOP (NSSA_LSDB(area), rn, lsa)
		ospf_discard_from_db(area->ospf, area->lsdb, lsa);
	LSDB_LOOP (OPAQUE_AREA_LSDB(area), rn, lsa)
		ospf_discard_from_db(area->ospf, area->lsdb, lsa);
	LSDB_LOOP (OPAQUE_LINK_LSDB(area), rn, lsa)
		ospf_discard_from_db(area->ospf, area->lsdb, lsa);

	ospf_lsdb_delete_all(area->lsdb);
}

static void ospf_area_free(struct ospf_area *area)
{
	ospf_opaque_type10_lsa_term(area);

	/* Free LSDBs. */
	ospf_area_lsdb_discard_delete(area);

	ospf_lsdb_free(area->lsdb);

	ospf_lsa_unlock(&area->router_lsa_self);

	route_table_finish(area->ranges);
	route_table_finish(area->nssa_ranges);
	list_delete(&area->oiflist);

	if (EXPORT_NAME(area))
		free(EXPORT_NAME(area));

	if (IMPORT_NAME(area))
		free(IMPORT_NAME(area));

	/* Cancel timer. */
	EVENT_OFF(area->t_stub_router);
	EVENT_OFF(area->t_opaque_lsa_self);

	if (OSPF_IS_AREA_BACKBONE(area))
		area->ospf->backbone = NULL;

	XFREE(MTYPE_OSPF_AREA, area);
}

void ospf_area_check_free(struct ospf *ospf, struct in_addr area_id)
{
	struct ospf_area *area;

	area = ospf_area_lookup_by_area_id(ospf, area_id);
	if (area && listcount(area->oiflist) == 0 &&
	    area->ranges->top == NULL && area->nssa_ranges->top == NULL &&
	    !ospf_vl_count(ospf, area) &&
	    area->shortcut_configured == OSPF_SHORTCUT_DEFAULT &&
	    area->external_routing == OSPF_AREA_DEFAULT &&
	    area->no_summary == 0 && area->default_cost == 1 &&
	    EXPORT_NAME(area) == NULL && IMPORT_NAME(area) == NULL &&
	    area->auth_type == OSPF_AUTH_NULL) {
		listnode_delete(ospf->areas, area);
		ospf_area_free(area);
	}
}

struct ospf_area *ospf_area_get(struct ospf *ospf, struct in_addr area_id)
{
	struct ospf_area *area;

	area = ospf_area_lookup_by_area_id(ospf, area_id);
	if (!area) {
		area = ospf_area_new(ospf, area_id);
		listnode_add_sort(ospf->areas, area);
		ospf_check_abr_status(ospf);
		if (ospf->stub_router_admin_set
		    == OSPF_STUB_ROUTER_ADMINISTRATIVE_SET) {
			SET_FLAG(area->stub_router_state,
				 OSPF_AREA_ADMIN_STUB_ROUTED);
		}
	}

	return area;
}

struct ospf_area *ospf_area_lookup_by_area_id(struct ospf *ospf,
					      struct in_addr area_id)
{
	struct ospf_area *area;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area))
		if (IPV4_ADDR_SAME(&area->area_id, &area_id))
			return area;

	return NULL;
}

void ospf_area_add_if(struct ospf_area *area, struct ospf_interface *oi)
{
	listnode_add(area->oiflist, oi);
}

void ospf_area_del_if(struct ospf_area *area, struct ospf_interface *oi)
{
	listnode_delete(area->oiflist, oi);
}


struct ospf_interface *add_ospf_interface(struct connected *co,
					  struct ospf_area *area)
{
	struct ospf_interface *oi;

	oi = ospf_if_new(area->ospf, co->ifp, co->address);
	oi->connected = co;

	oi->area = area;

	oi->params = ospf_lookup_if_params(co->ifp, oi->address->u.prefix4);
	oi->output_cost = ospf_if_get_output_cost(oi);

	/* Relate ospf interface to ospf instance. */
	oi->ospf = area->ospf;

	/* update network type as interface flag */
	/* If network type is specified previously,
	   skip network type setting. */
	oi->type = IF_DEF_PARAMS(co->ifp)->type;
	oi->ptp_dmvpn = IF_DEF_PARAMS(co->ifp)->ptp_dmvpn;
	oi->p2mp_delay_reflood = IF_DEF_PARAMS(co->ifp)->p2mp_delay_reflood;
	oi->p2mp_non_broadcast = IF_DEF_PARAMS(co->ifp)->p2mp_non_broadcast;

	/*
	 * If a neighbor filter is configured, update the neighbor filter
	 * for the interface.
	 */
	if (OSPF_IF_PARAM_CONFIGURED(IF_DEF_PARAMS(co->ifp), nbr_filter_name))
		oi->nbr_filter = prefix_list_lookup(AFI_IP,
						    IF_DEF_PARAMS(co->ifp)
							    ->nbr_filter_name);

	/* Add pseudo neighbor. */
	ospf_nbr_self_reset(oi, oi->ospf->router_id);

	ospf_area_add_if(oi->area, oi);

	/* if LDP-IGP Sync is configured globally inherit config */
	ospf_ldp_sync_if_init(oi);

	/*
	 * if router_id is not configured, don't bring up
	 * interfaces.
	 * ospf_router_id_update() will call ospf_if_update
	 * whenever r-id is configured instead.
	 */
	if ((area->ospf->router_id.s_addr != INADDR_ANY)
	    && if_is_operative(co->ifp))
		ospf_if_up(oi);

	/*
	 * RFC 3623 - Section 5 ("Unplanned Outages"):
	 * "The grace-LSAs are encapsulated in Link State Update Packets
	 * and sent out to all interfaces, even though the restarted
	 * router has no adjacencies and no knowledge of previous
	 * adjacencies".
	 */
	if (oi->ospf->gr_info.restart_in_progress &&
	    oi->ospf->gr_info.reason == OSPF_GR_UNKNOWN_RESTART)
		ospf_gr_unplanned_start_interface(oi);

	return oi;
}

static void update_redistributed(struct ospf *ospf, int add_to_ospf)
{
	struct route_node *rn;
	struct external_info *ei;
	struct ospf_external *ext;

	if (ospf_is_type_redistributed(ospf, ZEBRA_ROUTE_CONNECT, 0)) {
		ext = ospf_external_lookup(ospf, ZEBRA_ROUTE_CONNECT, 0);
		if ((ext) && EXTERNAL_INFO(ext)) {
			for (rn = route_top(EXTERNAL_INFO(ext)); rn;
			     rn = route_next(rn)) {
				ei = rn->info;
				if (ei == NULL)
					continue;

				if (add_to_ospf) {
					if (ospf_external_info_find_lsa(ospf,
									&ei->p))
						if (!ospf_redistribute_check(
							    ospf, ei, NULL))
							ospf_external_lsa_flush(
								ospf, ei->type,
								&ei->p,
								ei->ifindex /*, ei->nexthop */);
				} else {
					if (!ospf_external_info_find_lsa(
						    ospf, &ei->p))
						if (ospf_redistribute_check(
							    ospf, ei, NULL))
							ospf_external_lsa_originate(
								ospf, ei);
				}
			}
		}
	}
}

/* Config network statement related functions. */
static struct ospf_network *ospf_network_new(struct in_addr area_id)
{
	struct ospf_network *new;
	new = XCALLOC(MTYPE_OSPF_NETWORK, sizeof(struct ospf_network));

	new->area_id = area_id;
	new->area_id_fmt = OSPF_AREA_ID_FMT_DOTTEDQUAD;

	return new;
}

static void ospf_network_free(struct ospf *ospf, struct ospf_network *network)
{
	ospf_area_check_free(ospf, network->area_id);
	ospf_schedule_abr_task(ospf);
	XFREE(MTYPE_OSPF_NETWORK, network);
}

int ospf_network_set(struct ospf *ospf, struct prefix_ipv4 *p,
		     struct in_addr area_id, int df)
{
	struct ospf_network *network;
	struct ospf_area *area;
	struct route_node *rn;

	rn = route_node_get(ospf->networks, (struct prefix *)p);
	if (rn->info) {
		network = rn->info;
		route_unlock_node(rn);

		if (IPV4_ADDR_SAME(&area_id, &network->area_id)) {
			return 1;
		} else {
			/* There is already same network statement. */
			return 0;
		}
	}

	rn->info = network = ospf_network_new(area_id);
	network->area_id_fmt = df;
	area = ospf_area_get(ospf, area_id);
	ospf_area_display_format_set(ospf, area, df);

	/* Run network config now. */
	ospf_network_run((struct prefix *)p, area);

	/* Update connected redistribute. */
	update_redistributed(ospf, 1); /* interfaces possibly added */

	ospf_area_check_free(ospf, area_id);

	return 1;
}

int ospf_network_unset(struct ospf *ospf, struct prefix_ipv4 *p,
		       struct in_addr area_id)
{
	struct route_node *rn;
	struct ospf_network *network;
	struct listnode *node;
	struct ospf_interface *oi;
	struct list *ospf_oiflist = NULL;

	rn = route_node_lookup(ospf->networks, (struct prefix *)p);
	if (rn == NULL)
		return 0;

	network = rn->info;
	route_unlock_node(rn);
	if (!IPV4_ADDR_SAME(&area_id, &network->area_id))
		return 0;

	ospf_network_free(ospf, rn->info);
	rn->info = NULL;
	route_unlock_node(rn); /* initial reference */

	ospf_oiflist = list_dup(ospf->oiflist);
	/* Find interfaces that are not configured already. */
	for (ALL_LIST_ELEMENTS_RO(ospf_oiflist, node, oi)) {

		if (oi->type == OSPF_IFTYPE_VIRTUALLINK)
			continue;

		ospf_network_run_subnet(ospf, oi->connected, NULL, NULL);
	}

	list_delete(&ospf_oiflist);

	/* Update connected redistribute. */
	update_redistributed(ospf, 0); /* interfaces possibly removed */
	ospf_area_check_free(ospf, area_id);

	return 1;
}


/* Ensure there's an OSPF instance, as "ip ospf area" enabled OSPF means
 * there might not be any 'router ospf' config.
 *
 * Otherwise, doesn't do anything different to ospf_if_update for now
 */
void ospf_interface_area_set(struct ospf *ospf, struct interface *ifp)
{
	if (!ospf)
		return;

	ospf_if_update(ospf, ifp);
	/* if_update does a update_redistributed */

	return;
}

void ospf_interface_area_unset(struct ospf *ospf, struct interface *ifp)
{
	struct route_node *rn_oi;

	if (!ospf)
		return; /* Ospf not ready yet */

	/* Find interfaces that may need to be removed. */
	for (rn_oi = route_top(IF_OIFS(ifp)); rn_oi;
	     rn_oi = route_next(rn_oi)) {
		struct ospf_interface *oi = NULL;

		if ((oi = rn_oi->info) == NULL)
			continue;

		if (oi->type == OSPF_IFTYPE_VIRTUALLINK)
			continue;

		ospf_network_run_subnet(ospf, oi->connected, NULL, NULL);
	}

	/* Update connected redistribute. */
	update_redistributed(ospf, 0); /* interfaces possibly removed */
}

/* Check whether interface matches given network
 * returns: 1, true. 0, false
 */
static int ospf_network_match_iface(const struct connected *co,
				    const struct prefix *net)
{
	/* new approach: more elegant and conceptually clean */
	return prefix_match_network_statement(net, CONNECTED_PREFIX(co));
}

static void ospf_update_interface_area(struct connected *co,
				       struct ospf_area *area)
{
	struct ospf_interface *oi = ospf_if_table_lookup(co->ifp, co->address);

	/* nothing to be done case */
	if (oi && oi->area == area) {
		return;
	}

	if (oi)
		ospf_if_free(oi);

	add_ospf_interface(co, area);
}

/* Run OSPF for the given subnet, taking into account the following
 * possible sources of area configuration, in the given order of preference:
 *
 * - Whether there is interface+address specific area configuration
 * - Whether there is a default area for the interface
 * - Whether there is an area given as a parameter.
 * - If no specific network prefix/area is supplied, whether there's
 *   a matching network configured.
 */
static void ospf_network_run_subnet(struct ospf *ospf, struct connected *co,
				    struct prefix *p,
				    struct ospf_area *given_area)
{
	struct ospf_interface *oi;
	struct ospf_if_params *params;
	struct ospf_area *area = NULL;
	struct route_node *rn;
	int configed = 0;

	if (CHECK_FLAG(co->flags, ZEBRA_IFA_SECONDARY))
		return;

	if (co->address->family != AF_INET)
		return;

	/* Try determine the appropriate area for this interface + address
	 * Start by checking interface config
	 */
	params = ospf_lookup_if_params(co->ifp, co->address->u.prefix4);
	if (params && OSPF_IF_PARAM_CONFIGURED(params, if_area))
		area = ospf_area_get(ospf, params->if_area);
	else {
		params = IF_DEF_PARAMS(co->ifp);
		if (OSPF_IF_PARAM_CONFIGURED(params, if_area))
			area = ospf_area_get(ospf, params->if_area);
	}

	/* If we've found an interface and/or addr specific area, then we're
	 * done
	 */
	if (area) {
		ospf_update_interface_area(co, area);
		return;
	}

	/* Otherwise, only remaining possibility is a matching network statement
	 */
	if (p) {
		assert(given_area != NULL);

		/* Which either was supplied as a parameter.. (e.g. cause a new
		 * network/area was just added)..
		 */
		if (p->family == co->address->family
		    && ospf_network_match_iface(co, p))
			ospf_update_interface_area(co, given_area);

		return;
	}

	/* Else we have to search the existing network/area config to see
	 * if any match..
	 */
	for (rn = route_top(ospf->networks); rn; rn = route_next(rn))
		if (rn->info != NULL && ospf_network_match_iface(co, &rn->p)) {
			struct ospf_network *network =
				(struct ospf_network *)rn->info;
			area = ospf_area_get(ospf, network->area_id);
			ospf_update_interface_area(co, area);
			configed = 1;
		}

	/* If the subnet isn't in any area, deconfigure */
	if (!configed && (oi = ospf_if_table_lookup(co->ifp, co->address)))
		ospf_if_free(oi);
}

static void ospf_network_run_interface(struct ospf *ospf, struct interface *ifp,
				       struct prefix *p,
				       struct ospf_area *given_area)
{
	struct connected *co;

	if (memcmp(ifp->name, "VLINK", 5) == 0)
		return;

	/* Network prefix without area is nonsensical */
	if (p)
		assert(given_area != NULL);

	/* if interface prefix is match specified prefix,
	   then create socket and join multicast group. */
	frr_each (if_connected, ifp->connected, co)
		ospf_network_run_subnet(ospf, co, p, given_area);
}

static void ospf_network_run(struct prefix *p, struct ospf_area *area)
{
	struct vrf *vrf = vrf_lookup_by_id(area->ospf->vrf_id);
	struct interface *ifp;

	/* Schedule Router ID Update. */
	if (area->ospf->router_id.s_addr == INADDR_ANY)
		ospf_router_id_update(area->ospf);

	/* Get target interface. */
	FOR_ALL_INTERFACES (vrf, ifp)
		ospf_network_run_interface(area->ospf, ifp, p, area);
}

void ospf_ls_upd_queue_empty(struct ospf_interface *oi)
{
	struct route_node *rn;
	struct listnode *node, *nnode;
	struct list *lst;
	struct ospf_lsa *lsa;

	/* empty ls update queue */
	for (rn = route_top(oi->ls_upd_queue); rn; rn = route_next(rn))
		if ((lst = (struct list *)rn->info)) {
			for (ALL_LIST_ELEMENTS(lst, node, nnode, lsa))
				ospf_lsa_unlock(&lsa); /* oi->ls_upd_queue */
			list_delete(&lst);
			rn->info = NULL;
		}

	/* remove update event */
	EVENT_OFF(oi->t_ls_upd_event);
}

void ospf_if_update(struct ospf *ospf, struct interface *ifp)
{

	if (!ospf)
		return;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug(
			"%s: interface %s vrf %s(%u) ospf vrf %s vrf_id %u router_id %pI4",
			__func__, ifp->name, ifp->vrf->name, ifp->vrf->vrf_id,
			ospf_vrf_id_to_name(ospf->vrf_id), ospf->vrf_id,
			&ospf->router_id);

	/* OSPF must be ready. */
	if (!ospf_is_ready(ospf))
		return;

	ospf_network_run_interface(ospf, ifp, NULL, NULL);

	/* Update connected redistribute. */
	update_redistributed(ospf, 1);

}

void ospf_remove_vls_through_area(struct ospf *ospf, struct ospf_area *area)
{
	struct listnode *node, *nnode;
	struct ospf_vl_data *vl_data;

	for (ALL_LIST_ELEMENTS(ospf->vlinks, node, nnode, vl_data))
		if (IPV4_ADDR_SAME(&vl_data->vl_area_id, &area->area_id))
			ospf_vl_delete(ospf, vl_data);
}


static const struct message ospf_area_type_msg[] = {
	{OSPF_AREA_DEFAULT, "Default"},
	{OSPF_AREA_STUB, "Stub"},
	{OSPF_AREA_NSSA, "NSSA"},
	{0}};

static void ospf_area_type_set(struct ospf_area *area, int type)
{
	struct listnode *node;
	struct ospf_interface *oi;

	if (area->external_routing == type) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("Area[%pI4]: Types are the same, ignored.",
				   &area->area_id);
		return;
	}

	area->external_routing = type;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("Area[%pI4]: Configured as %s",
			   &area->area_id,
			   lookup_msg(ospf_area_type_msg, type, NULL));

	switch (area->external_routing) {
	case OSPF_AREA_DEFAULT:
		for (ALL_LIST_ELEMENTS_RO(area->oiflist, node, oi))
			if (oi->nbr_self != NULL) {
				UNSET_FLAG(oi->nbr_self->options,
					   OSPF_OPTION_NP);
				SET_FLAG(oi->nbr_self->options, OSPF_OPTION_E);
			}
		break;
	case OSPF_AREA_STUB:
		for (ALL_LIST_ELEMENTS_RO(area->oiflist, node, oi))
			if (oi->nbr_self != NULL) {
				if (IS_DEBUG_OSPF_EVENT)
					zlog_debug(
						"setting options on %s accordingly",
						IF_NAME(oi));
				UNSET_FLAG(oi->nbr_self->options,
					   OSPF_OPTION_NP);
				UNSET_FLAG(oi->nbr_self->options,
					   OSPF_OPTION_E);
				if (IS_DEBUG_OSPF_EVENT)
					zlog_debug("options set on %s: %x",
						   IF_NAME(oi), OPTIONS(oi));
			}
		break;
	case OSPF_AREA_NSSA:
		for (ALL_LIST_ELEMENTS_RO(area->oiflist, node, oi))
			if (oi->nbr_self != NULL) {
				zlog_debug(
					"setting nssa options on %s accordingly",
					IF_NAME(oi));
				UNSET_FLAG(oi->nbr_self->options,
					   OSPF_OPTION_E);
				SET_FLAG(oi->nbr_self->options, OSPF_OPTION_NP);
				zlog_debug("options set on %s: %x", IF_NAME(oi),
					   OPTIONS(oi));
			}
		break;
	default:
		break;
	}

	ospf_router_lsa_update_area(area);
	ospf_schedule_abr_task(area->ospf);
}

int ospf_area_shortcut_set(struct ospf *ospf, struct ospf_area *area, int mode)
{
	if (area->shortcut_configured == mode)
		return 0;

	area->shortcut_configured = mode;
	ospf_router_lsa_update_area(area);
	ospf_schedule_abr_task(ospf);

	ospf_area_check_free(ospf, area->area_id);

	return 1;
}

int ospf_area_shortcut_unset(struct ospf *ospf, struct ospf_area *area)
{
	area->shortcut_configured = OSPF_SHORTCUT_DEFAULT;
	ospf_router_lsa_update_area(area);
	ospf_area_check_free(ospf, area->area_id);
	ospf_schedule_abr_task(ospf);

	return 1;
}

static int ospf_area_vlink_count(struct ospf *ospf, struct ospf_area *area)
{
	struct ospf_vl_data *vl;
	struct listnode *node;
	int count = 0;

	for (ALL_LIST_ELEMENTS_RO(ospf->vlinks, node, vl))
		if (IPV4_ADDR_SAME(&vl->vl_area_id, &area->area_id))
			count++;

	return count;
}

int ospf_area_display_format_set(struct ospf *ospf, struct ospf_area *area,
				 int df)
{
	area->area_id_fmt = df;

	return 1;
}

int ospf_area_stub_set(struct ospf *ospf, struct in_addr area_id)
{
	struct ospf_area *area;

	area = ospf_area_get(ospf, area_id);
	if (ospf_area_vlink_count(ospf, area))
		return 0;

	if (area->external_routing != OSPF_AREA_STUB)
		ospf_area_type_set(area, OSPF_AREA_STUB);

	return 1;
}

int ospf_area_stub_unset(struct ospf *ospf, struct in_addr area_id)
{
	struct ospf_area *area;

	area = ospf_area_lookup_by_area_id(ospf, area_id);
	if (area == NULL)
		return 1;

	if (area->external_routing == OSPF_AREA_STUB)
		ospf_area_type_set(area, OSPF_AREA_DEFAULT);

	ospf_area_check_free(ospf, area_id);

	return 1;
}

int ospf_area_no_summary_set(struct ospf *ospf, struct in_addr area_id)
{
	struct ospf_area *area;

	area = ospf_area_get(ospf, area_id);
	area->no_summary = 1;

	return 1;
}

int ospf_area_no_summary_unset(struct ospf *ospf, struct in_addr area_id)
{
	struct ospf_area *area;

	area = ospf_area_lookup_by_area_id(ospf, area_id);
	if (area == NULL)
		return 0;

	area->no_summary = 0;
	ospf_area_check_free(ospf, area_id);

	return 1;
}

int ospf_area_nssa_no_summary_set(struct ospf *ospf, struct in_addr area_id)
{
	struct ospf_area *area;

	area = ospf_area_get(ospf, area_id);
	if (ospf_area_vlink_count(ospf, area))
		return 0;

	if (area->external_routing != OSPF_AREA_NSSA) {
		ospf_area_type_set(area, OSPF_AREA_NSSA);
		ospf->anyNSSA++;
		area->NSSATranslatorRole = OSPF_NSSA_ROLE_CANDIDATE;
	}

	ospf_area_no_summary_set(ospf, area_id);

	return 1;
}

int ospf_area_nssa_set(struct ospf *ospf, struct in_addr area_id)
{
	struct ospf_area *area;

	area = ospf_area_get(ospf, area_id);
	if (ospf_area_vlink_count(ospf, area))
		return 0;

	if (area->external_routing != OSPF_AREA_NSSA) {
		ospf_area_type_set(area, OSPF_AREA_NSSA);
		ospf->anyNSSA++;

		/* set NSSA area defaults */
		area->no_summary = 0;
		area->suppress_fa = 0;
		area->NSSATranslatorRole = OSPF_NSSA_ROLE_CANDIDATE;
		area->NSSATranslatorState = OSPF_NSSA_TRANSLATE_DISABLED;
		area->NSSATranslatorStabilityInterval =
			OSPF_NSSA_TRANS_STABLE_DEFAULT;
	}
	return 1;
}

int ospf_area_nssa_unset(struct ospf *ospf, struct in_addr area_id)
{
	struct ospf_area *area;

	area = ospf_area_lookup_by_area_id(ospf, area_id);
	if (area == NULL)
		return 0;

	ospf->anyNSSA--;
	/* set NSSA area defaults */
	area->no_summary = 0;
	area->suppress_fa = 0;
	area->NSSATranslatorRole = OSPF_NSSA_ROLE_CANDIDATE;
	area->NSSATranslatorState = OSPF_NSSA_TRANSLATE_DISABLED;
	area->NSSATranslatorStabilityInterval = OSPF_NSSA_TRANS_STABLE_DEFAULT;
	ospf_area_type_set(area, OSPF_AREA_DEFAULT);
	ospf_area_check_free(ospf, area_id);

	return 1;
}

int ospf_area_nssa_suppress_fa_set(struct ospf *ospf, struct in_addr area_id)
{
	struct ospf_area *area;

	area = ospf_area_lookup_by_area_id(ospf, area_id);
	if (area == NULL)
		return 0;

	area->suppress_fa = 1;

	return 1;
}

int ospf_area_nssa_suppress_fa_unset(struct ospf *ospf, struct in_addr area_id)
{
	struct ospf_area *area;

	area = ospf_area_lookup_by_area_id(ospf, area_id);
	if (area == NULL)
		return 0;

	area->suppress_fa = 0;

	return 1;
}

int ospf_area_nssa_translator_role_set(struct ospf *ospf,
				       struct in_addr area_id, int role)
{
	struct ospf_area *area;

	area = ospf_area_lookup_by_area_id(ospf, area_id);
	if (area == NULL)
		return 0;

	if (role != area->NSSATranslatorRole) {
		if ((area->NSSATranslatorRole == OSPF_NSSA_ROLE_ALWAYS)
		    || (role == OSPF_NSSA_ROLE_ALWAYS)) {
			/* RFC 3101 3.1
			 * if new role is OSPF_NSSA_ROLE_ALWAYS we need to set
			 * Nt bit, if the role was OSPF_NSSA_ROLE_ALWAYS we need
			 * to clear Nt bit
			 */
			area->NSSATranslatorRole = role;
			ospf_router_lsa_update_area(area);
		} else
			area->NSSATranslatorRole = role;
	}

	return 1;
}

void ospf_area_nssa_default_originate_set(struct ospf *ospf,
					  struct in_addr area_id, int metric,
					  int metric_type)
{
	struct ospf_area *area;

	area = ospf_area_lookup_by_area_id(ospf, area_id);
	if (area == NULL)
		return;

	if (!area->nssa_default_originate.enabled) {
		area->nssa_default_originate.enabled = true;
		if (++ospf->nssa_default_import_check.refcnt == 1) {
			ospf->nssa_default_import_check.status = false;
			ospf_zebra_import_default_route(ospf, false);
		}
	}

	area->nssa_default_originate.metric_value = metric;
	area->nssa_default_originate.metric_type = metric_type;
}

void ospf_area_nssa_default_originate_unset(struct ospf *ospf,
					    struct in_addr area_id)
{
	struct ospf_area *area;

	area = ospf_area_lookup_by_area_id(ospf, area_id);
	if (area == NULL)
		return;

	if (area->nssa_default_originate.enabled) {
		area->nssa_default_originate.enabled = false;
		if (--ospf->nssa_default_import_check.refcnt == 0) {
			ospf->nssa_default_import_check.status = false;
			ospf_zebra_import_default_route(ospf, true);
		}
		area->nssa_default_originate.metric_value = -1;
		area->nssa_default_originate.metric_type = -1;

		if (!IS_OSPF_ABR(ospf))
			ospf_abr_nssa_type7_defaults(ospf);
	}
}

int ospf_area_export_list_set(struct ospf *ospf, struct ospf_area *area,
			      const char *list_name)
{
	struct access_list *list;
	list = access_list_lookup(AFI_IP, list_name);

	EXPORT_LIST(area) = list;

	if (EXPORT_NAME(area))
		free(EXPORT_NAME(area));

	EXPORT_NAME(area) = strdup(list_name);
	ospf_schedule_abr_task(ospf);

	return 1;
}

int ospf_area_export_list_unset(struct ospf *ospf, struct ospf_area *area)
{

	EXPORT_LIST(area) = 0;

	if (EXPORT_NAME(area))
		free(EXPORT_NAME(area));

	EXPORT_NAME(area) = NULL;

	ospf_area_check_free(ospf, area->area_id);

	ospf_schedule_abr_task(ospf);

	return 1;
}

int ospf_area_import_list_set(struct ospf *ospf, struct ospf_area *area,
			      const char *name)
{
	struct access_list *list;
	list = access_list_lookup(AFI_IP, name);

	IMPORT_LIST(area) = list;

	if (IMPORT_NAME(area))
		free(IMPORT_NAME(area));

	IMPORT_NAME(area) = strdup(name);
	ospf_schedule_abr_task(ospf);

	return 1;
}

int ospf_area_import_list_unset(struct ospf *ospf, struct ospf_area *area)
{
	IMPORT_LIST(area) = 0;

	if (IMPORT_NAME(area))
		free(IMPORT_NAME(area));

	IMPORT_NAME(area) = NULL;
	ospf_area_check_free(ospf, area->area_id);

	ospf_schedule_abr_task(ospf);

	return 1;
}

int ospf_timers_refresh_set(struct ospf *ospf, int interval)
{
	int time_left;

	if (ospf->lsa_refresh_interval == interval)
		return 1;

	time_left = ospf->lsa_refresh_interval
		    - (monotime(NULL) - ospf->lsa_refresher_started);

	if (time_left > interval) {
		EVENT_OFF(ospf->t_lsa_refresher);
		event_add_timer(master, ospf_lsa_refresh_walker, ospf, interval,
				&ospf->t_lsa_refresher);
	}
	ospf->lsa_refresh_interval = interval;

	return 1;
}

int ospf_timers_refresh_unset(struct ospf *ospf)
{
	int time_left;

	time_left = ospf->lsa_refresh_interval
		    - (monotime(NULL) - ospf->lsa_refresher_started);

	if (time_left > OSPF_LSA_REFRESH_INTERVAL_DEFAULT) {
		EVENT_OFF(ospf->t_lsa_refresher);
		ospf->t_lsa_refresher = NULL;
		event_add_timer(master, ospf_lsa_refresh_walker, ospf,
				OSPF_LSA_REFRESH_INTERVAL_DEFAULT,
				&ospf->t_lsa_refresher);
	}

	ospf->lsa_refresh_interval = OSPF_LSA_REFRESH_INTERVAL_DEFAULT;

	return 1;
}


static struct ospf_nbr_nbma *ospf_nbr_nbma_new(void)
{
	struct ospf_nbr_nbma *nbr_nbma;

	nbr_nbma = XCALLOC(MTYPE_OSPF_NEIGHBOR_STATIC,
			   sizeof(struct ospf_nbr_nbma));

	nbr_nbma->priority = OSPF_NEIGHBOR_PRIORITY_DEFAULT;
	nbr_nbma->v_poll = OSPF_POLL_INTERVAL_DEFAULT;

	return nbr_nbma;
}

static void ospf_nbr_nbma_free(struct ospf_nbr_nbma *nbr_nbma)
{
	XFREE(MTYPE_OSPF_NEIGHBOR_STATIC, nbr_nbma);
}

static void ospf_nbr_nbma_delete(struct ospf *ospf,
				 struct ospf_nbr_nbma *nbr_nbma)
{
	struct route_node *rn;
	struct prefix_ipv4 p;

	p.family = AF_INET;
	p.prefix = nbr_nbma->addr;
	p.prefixlen = IPV4_MAX_BITLEN;

	rn = route_node_lookup(ospf->nbr_nbma, (struct prefix *)&p);
	if (rn) {
		ospf_nbr_nbma_free(rn->info);
		rn->info = NULL;
		route_unlock_node(rn);
		route_unlock_node(rn);
	}
}

static void ospf_nbr_nbma_down(struct ospf_nbr_nbma *nbr_nbma)
{
	EVENT_OFF(nbr_nbma->t_poll);

	if (nbr_nbma->nbr) {
		nbr_nbma->nbr->nbr_nbma = NULL;
		OSPF_NSM_EVENT_EXECUTE(nbr_nbma->nbr, NSM_KillNbr);
	}

	if (nbr_nbma->oi)
		listnode_delete(nbr_nbma->oi->nbr_nbma, nbr_nbma);
}

static void ospf_nbr_nbma_add(struct ospf_nbr_nbma *nbr_nbma,
			      struct ospf_interface *oi)
{
	struct ospf_neighbor *nbr;
	struct route_node *rn;
	struct prefix p;

	if (!OSPF_IF_NON_BROADCAST(oi))
		return;

	if (nbr_nbma->nbr != NULL)
		return;

	if (IPV4_ADDR_SAME(&oi->nbr_self->address.u.prefix4, &nbr_nbma->addr))
		return;

	nbr_nbma->oi = oi;
	listnode_add(oi->nbr_nbma, nbr_nbma);

	/* Get neighbor information from table. */
	p.family = AF_INET;
	p.prefixlen = IPV4_MAX_BITLEN;
	p.u.prefix4 = nbr_nbma->addr;

	rn = route_node_get(oi->nbrs, &p);
	if (rn->info) {
		nbr = rn->info;
		nbr->nbr_nbma = nbr_nbma;
		nbr_nbma->nbr = nbr;

		route_unlock_node(rn);
	} else {
		nbr = rn->info = ospf_nbr_new(oi);
		nbr->state = NSM_Down;
		nbr->src = nbr_nbma->addr;
		nbr->nbr_nbma = nbr_nbma;
		nbr->priority = nbr_nbma->priority;
		nbr->address = p;

		nbr_nbma->nbr = nbr;

		/* Configure BFD if interface has it. */
		ospf_neighbor_bfd_apply(nbr);

		OSPF_NSM_EVENT_EXECUTE(nbr, NSM_Start);
	}
}

void ospf_nbr_nbma_if_update(struct ospf *ospf, struct ospf_interface *oi)
{
	struct ospf_nbr_nbma *nbr_nbma;
	struct route_node *rn;
	struct prefix_ipv4 p;

	if (!OSPF_IF_NON_BROADCAST(oi))
		return;

	for (rn = route_top(ospf->nbr_nbma); rn; rn = route_next(rn))
		if ((nbr_nbma = rn->info))
			if (nbr_nbma->oi == NULL && nbr_nbma->nbr == NULL) {
				p.family = AF_INET;
				p.prefix = nbr_nbma->addr;
				p.prefixlen = IPV4_MAX_BITLEN;

				if (prefix_match(oi->address,
						 (struct prefix *)&p))
					ospf_nbr_nbma_add(nbr_nbma, oi);
			}
}

struct ospf_nbr_nbma *ospf_nbr_nbma_lookup(struct ospf *ospf,
					   struct in_addr nbr_addr)
{
	struct route_node *rn;
	struct prefix_ipv4 p;

	p.family = AF_INET;
	p.prefix = nbr_addr;
	p.prefixlen = IPV4_MAX_BITLEN;

	rn = route_node_lookup(ospf->nbr_nbma, (struct prefix *)&p);
	if (rn) {
		route_unlock_node(rn);
		return rn->info;
	}
	return NULL;
}

int ospf_nbr_nbma_set(struct ospf *ospf, struct in_addr nbr_addr)
{
	struct ospf_nbr_nbma *nbr_nbma;
	struct ospf_interface *oi;
	struct prefix_ipv4 p;
	struct route_node *rn;
	struct listnode *node;

	nbr_nbma = ospf_nbr_nbma_lookup(ospf, nbr_addr);
	if (nbr_nbma)
		return 0;

	nbr_nbma = ospf_nbr_nbma_new();
	nbr_nbma->addr = nbr_addr;

	p.family = AF_INET;
	p.prefix = nbr_addr;
	p.prefixlen = IPV4_MAX_BITLEN;

	rn = route_node_get(ospf->nbr_nbma, (struct prefix *)&p);
	if (rn->info)
		route_unlock_node(rn);
	rn->info = nbr_nbma;

	for (ALL_LIST_ELEMENTS_RO(ospf->oiflist, node, oi)) {
		if (OSPF_IF_NON_BROADCAST(oi))
			if (prefix_match(oi->address, (struct prefix *)&p)) {
				ospf_nbr_nbma_add(nbr_nbma, oi);
				break;
			}
	}

	return 1;
}

int ospf_nbr_nbma_unset(struct ospf *ospf, struct in_addr nbr_addr)
{
	struct ospf_nbr_nbma *nbr_nbma;

	nbr_nbma = ospf_nbr_nbma_lookup(ospf, nbr_addr);
	if (nbr_nbma == NULL)
		return 0;

	ospf_nbr_nbma_down(nbr_nbma);
	ospf_nbr_nbma_delete(ospf, nbr_nbma);

	return 1;
}

int ospf_nbr_nbma_priority_set(struct ospf *ospf, struct in_addr nbr_addr,
			       uint8_t priority)
{
	struct ospf_nbr_nbma *nbr_nbma;

	nbr_nbma = ospf_nbr_nbma_lookup(ospf, nbr_addr);
	if (nbr_nbma == NULL)
		return 0;

	if (nbr_nbma->priority != priority)
		nbr_nbma->priority = priority;

	return 1;
}

int ospf_nbr_nbma_priority_unset(struct ospf *ospf, struct in_addr nbr_addr)
{
	struct ospf_nbr_nbma *nbr_nbma;

	nbr_nbma = ospf_nbr_nbma_lookup(ospf, nbr_addr);
	if (nbr_nbma == NULL)
		return 0;

	if (nbr_nbma != OSPF_NEIGHBOR_PRIORITY_DEFAULT)
		nbr_nbma->priority = OSPF_NEIGHBOR_PRIORITY_DEFAULT;

	return 1;
}

int ospf_nbr_nbma_poll_interval_set(struct ospf *ospf, struct in_addr nbr_addr,
				    unsigned int interval)
{
	struct ospf_nbr_nbma *nbr_nbma;

	nbr_nbma = ospf_nbr_nbma_lookup(ospf, nbr_addr);
	if (nbr_nbma == NULL)
		return 0;

	if (nbr_nbma->v_poll != interval) {
		nbr_nbma->v_poll = interval;
		if (nbr_nbma->oi && ospf_if_is_up(nbr_nbma->oi)) {
			EVENT_OFF(nbr_nbma->t_poll);
			OSPF_POLL_TIMER_ON(nbr_nbma->t_poll, ospf_poll_timer,
					   nbr_nbma->v_poll);
		}
	}

	return 1;
}

int ospf_nbr_nbma_poll_interval_unset(struct ospf *ospf, struct in_addr addr)
{
	struct ospf_nbr_nbma *nbr_nbma;

	nbr_nbma = ospf_nbr_nbma_lookup(ospf, addr);
	if (nbr_nbma == NULL)
		return 0;

	if (nbr_nbma->v_poll != OSPF_POLL_INTERVAL_DEFAULT)
		nbr_nbma->v_poll = OSPF_POLL_INTERVAL_DEFAULT;

	return 1;
}

/*
 * Update socket bufsize(s), usually after config change
 */
void ospf_update_bufsize(struct ospf *ospf, uint32_t recvsize,
			 uint32_t sendsize)
{
	enum ospf_sock_type_e type = OSPF_SOCK_NONE;

	/* Figure out whether there's been a change */
	if (recvsize != ospf->recv_sock_bufsize) {
		type = OSPF_SOCK_RECV;
		ospf->recv_sock_bufsize = recvsize;

		if (sendsize != ospf->send_sock_bufsize) {
			type = OSPF_SOCK_BOTH;
			ospf->send_sock_bufsize = sendsize;
		}
	} else if (sendsize != ospf->send_sock_bufsize) {
		type = OSPF_SOCK_SEND;
		ospf->send_sock_bufsize = sendsize;
	}

	if (type != OSPF_SOCK_NONE)
		ospf_sock_bufsize_update(ospf, ospf->fd, type);
}

void ospf_master_init(struct event_loop *master)
{
	memset(&ospf_master, 0, sizeof(ospf_master));

	om = &ospf_master;
	om->ospf = list_new();
	om->master = master;
}

/* Link OSPF instance to VRF. */
void ospf_vrf_link(struct ospf *ospf, struct vrf *vrf)
{
	ospf->vrf_id = vrf->vrf_id;
	if (vrf->info != (void *)ospf)
		vrf->info = (void *)ospf;
}

/* Unlink OSPF instance from VRF. */
void ospf_vrf_unlink(struct ospf *ospf, struct vrf *vrf)
{
	if (vrf->info == (void *)ospf)
		vrf->info = NULL;
	ospf->vrf_id = VRF_UNKNOWN;
}

/* This is hook function for vrf create called as part of vrf_init */
static int ospf_vrf_new(struct vrf *vrf)
{
	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: VRF Created: %s(%u)", __func__, vrf->name,
			   vrf->vrf_id);

	return 0;
}

/* This is hook function for vrf delete call as part of vrf_init */
static int ospf_vrf_delete(struct vrf *vrf)
{
	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: VRF Deletion: %s(%u)", __func__, vrf->name,
			   vrf->vrf_id);

	return 0;
}

static void ospf_set_redist_vrf_bitmaps(struct ospf *ospf, bool set)
{
	int type;
	struct list *red_list;

	for (type = 0; type < ZEBRA_ROUTE_MAX; type++) {
		red_list = ospf->redist[type];
		if (!red_list)
			continue;
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug(
				"%s: setting redist vrf %d bitmap for type %d",
				__func__, ospf->vrf_id, type);
		if (set)
			vrf_bitmap_set(&zclient->redist[AFI_IP][type],
				       ospf->vrf_id);
		else
			vrf_bitmap_unset(&zclient->redist[AFI_IP][type],
					 ospf->vrf_id);
	}

	red_list = ospf->redist[DEFAULT_ROUTE];
	if (red_list) {
		if (set)
			vrf_bitmap_set(&zclient->default_information[AFI_IP],
				       ospf->vrf_id);
		else
			vrf_bitmap_unset(&zclient->default_information[AFI_IP],
					 ospf->vrf_id);
	}
}

/* Enable OSPF VRF instance */
static int ospf_vrf_enable(struct vrf *vrf)
{
	struct ospf *ospf = NULL;
	vrf_id_t old_vrf_id;
	int ret = 0;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: VRF %s id %u enabled", __func__, vrf->name,
			   vrf->vrf_id);

	ospf = ospf_lookup_by_name(vrf->name);
	if (ospf) {
		old_vrf_id = ospf->vrf_id;
		/* We have instance configured, link to VRF and make it "up". */
		ospf_vrf_link(ospf, vrf);
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug(
				"%s: ospf linked to vrf %s vrf_id %u (old id %u)",
				__func__, vrf->name, ospf->vrf_id, old_vrf_id);

		if (old_vrf_id != ospf->vrf_id) {
			ospf_set_redist_vrf_bitmaps(ospf, true);

			/* start zebra redist to us for new vrf */
			ospf_zebra_vrf_register(ospf);

			ret = ospf_sock_init(ospf);
			if (ret < 0 || ospf->fd <= 0)
				return 0;
			event_add_read(master, ospf_read, ospf, ospf->fd,
				       &ospf->t_read);
			ospf->oi_running = 1;
			ospf_router_id_update(ospf);
		}
	}

	return 0;
}

/* Disable OSPF VRF instance */
static int ospf_vrf_disable(struct vrf *vrf)
{
	struct ospf *ospf = NULL;
	vrf_id_t old_vrf_id = VRF_UNKNOWN;

	if (vrf->vrf_id == VRF_DEFAULT)
		return 0;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: VRF %s id %d disabled.", __func__, vrf->name,
			   vrf->vrf_id);

	ospf = ospf_lookup_by_name(vrf->name);
	if (ospf) {
		old_vrf_id = ospf->vrf_id;

		ospf_zebra_vrf_deregister(ospf);

		ospf_set_redist_vrf_bitmaps(ospf, false);

		/* We have instance configured, unlink
		 * from VRF and make it "down".
		 */
		ospf_vrf_unlink(ospf, vrf);
		ospf->oi_running = 0;
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: ospf old_vrf_id %d unlinked", __func__,
				   old_vrf_id);
		EVENT_OFF(ospf->t_read);
		close(ospf->fd);
		ospf->fd = -1;
	}

	/* Note: This is a callback, the VRF will be deleted by the caller. */
	return 0;
}

void ospf_vrf_init(void)
{
	vrf_init(ospf_vrf_new, ospf_vrf_enable, ospf_vrf_disable,
		 ospf_vrf_delete);
}

void ospf_vrf_terminate(void)
{
	vrf_terminate();
}

const char *ospf_vrf_id_to_name(vrf_id_t vrf_id)
{
	struct vrf *vrf = vrf_lookup_by_id(vrf_id);

	return vrf ? vrf->name : "NIL";
}

const char *ospf_get_name(const struct ospf *ospf)
{
	if (ospf->name)
		return ospf->name;
	else
		return VRF_DEFAULT_NAME;
}
