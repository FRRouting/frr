// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2003 Yasuhiro Ohara
 */

#include <zebra.h>

#include "log.h"
#include "memory.h"
#include "frrevent.h"
#include "linklist.h"
#include "vty.h"
#include "command.h"
#include "lib/bfd.h"

#include "ospf6_proto.h"
#include "ospf6_lsa.h"
#include "ospf6_lsdb.h"
#include "ospf6_message.h"
#include "ospf6_top.h"
#include "ospf6_area.h"
#include "ospf6_interface.h"
#include "ospf6_neighbor.h"
#include "ospf6_intra.h"
#include "ospf6_flood.h"
#include "ospf6d.h"
#include "ospf6_bfd.h"
#include "ospf6_abr.h"
#include "ospf6_asbr.h"
#include "ospf6_lsa.h"
#include "ospf6_spf.h"
#include "ospf6_zebra.h"
#include "ospf6_gr.h"
#include "lib/json.h"

DEFINE_MTYPE_STATIC(OSPF6D, OSPF6_NEIGHBOR, "OSPF6 neighbor");
DEFINE_MTYPE_STATIC(OSPF6D, OSPF6_NEIGHBOR_P2XP_CFG,
		    "OSPF6 PtP/PtMP neighbor config");

static int ospf6_if_p2xp_neighcfg_cmp(const struct ospf6_if_p2xp_neighcfg *a,
				      const struct ospf6_if_p2xp_neighcfg *b);

DECLARE_RBTREE_UNIQ(ospf6_if_p2xp_neighcfgs, struct ospf6_if_p2xp_neighcfg,
		    item, ospf6_if_p2xp_neighcfg_cmp);

static void p2xp_neigh_refresh(struct ospf6_neighbor *on, uint32_t prev_cost);

DEFINE_HOOK(ospf6_neighbor_change,
	    (struct ospf6_neighbor * on, int state, int next_state),
	    (on, state, next_state));

unsigned char conf_debug_ospf6_neighbor = 0;

const char *const ospf6_neighbor_state_str[] = {
	"None",	   "Down",     "Attempt", "Init", "Twoway",
	"ExStart", "ExChange", "Loading", "Full", NULL
};

const char *const ospf6_neighbor_event_str[] = {
	"NoEvent",	"HelloReceived", "2-WayReceived",   "NegotiationDone",
	"ExchangeDone", "LoadingDone",	 "AdjOK?",	    "SeqNumberMismatch",
	"BadLSReq",	"1-WayReceived", "InactivityTimer",
};

int ospf6_neighbor_cmp(void *va, void *vb)
{
	struct ospf6_neighbor *ona = (struct ospf6_neighbor *)va;
	struct ospf6_neighbor *onb = (struct ospf6_neighbor *)vb;

	if (ona->router_id == onb->router_id)
		return 0;

	return (ntohl(ona->router_id) < ntohl(onb->router_id)) ? -1 : 1;
}

struct ospf6_neighbor *ospf6_neighbor_lookup(uint32_t router_id,
					     struct ospf6_interface *oi)
{
	struct listnode *n;
	struct ospf6_neighbor *on;

	for (ALL_LIST_ELEMENTS_RO(oi->neighbor_list, n, on))
		if (on->router_id == router_id)
			return on;

	return (struct ospf6_neighbor *)NULL;
}

struct ospf6_neighbor *ospf6_area_neighbor_lookup(struct ospf6_area *area,
						  uint32_t router_id)
{
	struct ospf6_interface *oi;
	struct ospf6_neighbor *nbr;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(area->if_list, node, oi)) {
		nbr = ospf6_neighbor_lookup(router_id, oi);
		if (nbr)
			return nbr;
	}

	return NULL;
}

static void ospf6_neighbor_clear_ls_lists(struct ospf6_neighbor *on)
{
	struct ospf6_lsa *lsa;
	struct ospf6_lsa *lsanext;

	ospf6_lsdb_remove_all(on->summary_list);
	if (on->last_ls_req) {
		ospf6_lsa_unlock(&on->last_ls_req);
		on->last_ls_req = NULL;
	}

	ospf6_lsdb_remove_all(on->request_list);
	for (ALL_LSDB(on->retrans_list, lsa, lsanext)) {
		ospf6_decrement_retrans_count(lsa);
		ospf6_lsdb_remove(lsa, on->retrans_list);
	}
}

/* create ospf6_neighbor */
struct ospf6_neighbor *ospf6_neighbor_create(uint32_t router_id,
					     struct ospf6_interface *oi)
{
	struct ospf6_neighbor *on;
	char buf[16];
	int type;

	on = XCALLOC(MTYPE_OSPF6_NEIGHBOR, sizeof(struct ospf6_neighbor));
	inet_ntop(AF_INET, &router_id, buf, sizeof(buf));
	snprintf(on->name, sizeof(on->name), "%s%%%s", buf, oi->interface->name);
	on->ospf6_if = oi;
	on->state = OSPF6_NEIGHBOR_DOWN;
	on->state_change = 0;
	monotime(&on->last_changed);
	on->router_id = router_id;

	on->summary_list = ospf6_lsdb_create(on);
	on->request_list = ospf6_lsdb_create(on);
	on->retrans_list = ospf6_lsdb_create(on);

	on->dbdesc_list = ospf6_lsdb_create(on);
	on->lsupdate_list = ospf6_lsdb_create(on);
	on->lsack_list = ospf6_lsdb_create(on);

	for (type = 0; type < OSPF6_MESSAGE_TYPE_MAX; type++) {
		on->seqnum_l[type] = 0;
		on->seqnum_h[type] = 0;
	}

	on->auth_present = false;

	listnode_add_sort(oi->neighbor_list, on);

	ospf6_bfd_info_nbr_create(oi, on);
	return on;
}

void ospf6_neighbor_delete(struct ospf6_neighbor *on)
{
	if (on->p2xp_cfg)
		on->p2xp_cfg->active = NULL;

	ospf6_neighbor_clear_ls_lists(on);

	ospf6_lsdb_remove_all(on->dbdesc_list);
	ospf6_lsdb_remove_all(on->lsupdate_list);
	ospf6_lsdb_remove_all(on->lsack_list);

	ospf6_lsdb_delete(on->summary_list);
	ospf6_lsdb_delete(on->request_list);
	ospf6_lsdb_delete(on->retrans_list);

	ospf6_lsdb_delete(on->dbdesc_list);
	ospf6_lsdb_delete(on->lsupdate_list);
	ospf6_lsdb_delete(on->lsack_list);

	EVENT_OFF(on->inactivity_timer);

	EVENT_OFF(on->last_dbdesc_release_timer);

	EVENT_OFF(on->thread_send_dbdesc);
	EVENT_OFF(on->thread_send_lsreq);
	EVENT_OFF(on->thread_send_lsupdate);
	EVENT_OFF(on->thread_send_lsack);
	EVENT_OFF(on->thread_exchange_done);
	EVENT_OFF(on->thread_adj_ok);
	EVENT_OFF(on->event_loading_done);

	EVENT_OFF(on->gr_helper_info.t_grace_timer);

	bfd_sess_free(&on->bfd_session);
	XFREE(MTYPE_OSPF6_NEIGHBOR, on);
}

void ospf6_neighbor_lladdr_set(struct ospf6_neighbor *on,
			       const struct in6_addr *addr)
{
	if (IPV6_ADDR_SAME(addr, &on->linklocal_addr))
		return;

	memcpy(&on->linklocal_addr, addr, sizeof(struct in6_addr));

	if (on->ospf6_if->type == OSPF_IFTYPE_POINTOPOINT ||
	    on->ospf6_if->type == OSPF_IFTYPE_POINTOMULTIPOINT) {
		uint32_t prev_cost = ospf6_neighbor_cost(on);

		p2xp_neigh_refresh(on, prev_cost);
	}
}

static void ospf6_neighbor_state_change(uint8_t next_state,
					struct ospf6_neighbor *on, int event)
{
	uint8_t prev_state;

	prev_state = on->state;
	on->state = next_state;

	if (prev_state == next_state)
		return;

	on->state_change++;
	monotime(&on->last_changed);

	/* log */
	if (IS_OSPF6_DEBUG_NEIGHBOR(STATE)) {
		zlog_debug("Neighbor state change %s (Router-ID: %pI4): [%s]->[%s] (%s)",
			   on->name, &on->router_id,
			   ospf6_neighbor_state_str[prev_state],
			   ospf6_neighbor_state_str[next_state],
			   ospf6_neighbor_event_string(event));
	}

	/* Optionally notify about adjacency changes */
	if (CHECK_FLAG(on->ospf6_if->area->ospf6->config_flags,
		       OSPF6_LOG_ADJACENCY_CHANGES) &&
	    (CHECK_FLAG(on->ospf6_if->area->ospf6->config_flags,
			OSPF6_LOG_ADJACENCY_DETAIL) ||
	     (next_state == OSPF6_NEIGHBOR_FULL) || (next_state < prev_state)))
		zlog_notice("AdjChg: Nbr %pI4(%s) on %s: %s -> %s (%s)",
			    &on->router_id,
			    vrf_id_to_name(on->ospf6_if->interface->vrf->vrf_id),
			    on->name, ospf6_neighbor_state_str[prev_state],
			    ospf6_neighbor_state_str[next_state],
			    ospf6_neighbor_event_string(event));

	if (prev_state == OSPF6_NEIGHBOR_FULL ||
	    next_state == OSPF6_NEIGHBOR_FULL) {
		if (!OSPF6_GR_IS_ACTIVE_HELPER(on)) {
			OSPF6_ROUTER_LSA_SCHEDULE(on->ospf6_if->area);
			if (on->ospf6_if->state == OSPF6_INTERFACE_DR) {
				OSPF6_NETWORK_LSA_SCHEDULE(on->ospf6_if);
				OSPF6_INTRA_PREFIX_LSA_SCHEDULE_TRANSIT(
					on->ospf6_if);
			}
		}
		if (next_state == OSPF6_NEIGHBOR_FULL)
			on->ospf6_if->area->intra_prefix_originate = 1;

		if (!OSPF6_GR_IS_ACTIVE_HELPER(on))
			OSPF6_INTRA_PREFIX_LSA_SCHEDULE_STUB(on->ospf6_if->area);

		if ((prev_state == OSPF6_NEIGHBOR_LOADING ||
		     prev_state == OSPF6_NEIGHBOR_EXCHANGE) &&
		    next_state == OSPF6_NEIGHBOR_FULL) {
			OSPF6_AS_EXTERN_LSA_SCHEDULE(on->ospf6_if);
			on->ospf6_if->area->full_nbrs++;
		}

		if (prev_state == OSPF6_NEIGHBOR_FULL)
			on->ospf6_if->area->full_nbrs--;
	}

	if ((prev_state == OSPF6_NEIGHBOR_EXCHANGE ||
	     prev_state == OSPF6_NEIGHBOR_LOADING) &&
	    (next_state != OSPF6_NEIGHBOR_EXCHANGE &&
	     next_state != OSPF6_NEIGHBOR_LOADING))
		ospf6_maxage_remove(on->ospf6_if->area->ospf6);

	hook_call(ospf6_neighbor_change, on, next_state, prev_state);
	ospf6_bfd_trigger_event(on, prev_state, next_state);
}

/* RFC2328 section 10.4 */
static int need_adjacency(struct ospf6_neighbor *on)
{
	if (on->ospf6_if->state == OSPF6_INTERFACE_POINTTOPOINT ||
	    on->ospf6_if->state == OSPF6_INTERFACE_POINTTOMULTIPOINT ||
	    on->ospf6_if->state == OSPF6_INTERFACE_DR ||
	    on->ospf6_if->state == OSPF6_INTERFACE_BDR)
		return 1;

	if (on->ospf6_if->drouter == on->router_id ||
	    on->ospf6_if->bdrouter == on->router_id)
		return 1;

	return 0;
}

void hello_received(struct event *thread)
{
	struct ospf6_neighbor *on;

	on = (struct ospf6_neighbor *)EVENT_ARG(thread);
	assert(on);

	if (IS_OSPF6_DEBUG_NEIGHBOR(EVENT))
		zlog_debug("Neighbor Event %s: *HelloReceived*", on->name);

	/* reset Inactivity Timer */
	EVENT_OFF(on->inactivity_timer);
	event_add_timer(master, inactivity_timer, on,
			on->ospf6_if->dead_interval, &on->inactivity_timer);

	if (on->state <= OSPF6_NEIGHBOR_DOWN)
		ospf6_neighbor_state_change(OSPF6_NEIGHBOR_INIT, on,
					    OSPF6_NEIGHBOR_EVENT_HELLO_RCVD);
}

void twoway_received(struct event *thread)
{
	struct ospf6_neighbor *on;

	on = (struct ospf6_neighbor *)EVENT_ARG(thread);
	assert(on);

	if (on->state > OSPF6_NEIGHBOR_INIT)
		return;

	if (IS_OSPF6_DEBUG_NEIGHBOR(EVENT))
		zlog_debug("Neighbor Event %s: *2Way-Received*", on->name);

	event_add_event(master, neighbor_change, on->ospf6_if, 0, NULL);

	if (!need_adjacency(on)) {
		ospf6_neighbor_state_change(OSPF6_NEIGHBOR_TWOWAY, on,
					    OSPF6_NEIGHBOR_EVENT_TWOWAY_RCVD);
		return;
	}

	ospf6_neighbor_state_change(OSPF6_NEIGHBOR_EXSTART, on,
				    OSPF6_NEIGHBOR_EVENT_TWOWAY_RCVD);
	SET_FLAG(on->dbdesc_bits, OSPF6_DBDESC_MSBIT);
	SET_FLAG(on->dbdesc_bits, OSPF6_DBDESC_MBIT);
	SET_FLAG(on->dbdesc_bits, OSPF6_DBDESC_IBIT);

	EVENT_OFF(on->thread_send_dbdesc);
	event_add_event(master, ospf6_dbdesc_send, on, 0,
			&on->thread_send_dbdesc);
}

void negotiation_done(struct event *thread)
{
	struct ospf6_neighbor *on;
	struct ospf6_lsa *lsa, *lsanext;

	on = (struct ospf6_neighbor *)EVENT_ARG(thread);
	assert(on);

	if (on->state != OSPF6_NEIGHBOR_EXSTART)
		return;

	if (IS_OSPF6_DEBUG_NEIGHBOR(EVENT))
		zlog_debug("Neighbor Event %s: *NegotiationDone*", on->name);

	/* clear ls-list */
	ospf6_neighbor_clear_ls_lists(on);

	/* Interface scoped LSAs */
	for (ALL_LSDB(on->ospf6_if->lsdb, lsa, lsanext)) {
		if (OSPF6_LSA_IS_MAXAGE(lsa)) {
			ospf6_increment_retrans_count(lsa);
			ospf6_lsdb_add(ospf6_lsa_copy(lsa), on->retrans_list);
		} else
			ospf6_lsdb_add(ospf6_lsa_copy(lsa), on->summary_list);
	}

	/* Area scoped LSAs */
	for (ALL_LSDB(on->ospf6_if->area->lsdb, lsa, lsanext)) {
		if (OSPF6_LSA_IS_MAXAGE(lsa)) {
			ospf6_increment_retrans_count(lsa);
			ospf6_lsdb_add(ospf6_lsa_copy(lsa), on->retrans_list);
		} else
			ospf6_lsdb_add(ospf6_lsa_copy(lsa), on->summary_list);
	}

	/* AS scoped LSAs */
	for (ALL_LSDB(on->ospf6_if->area->ospf6->lsdb, lsa, lsanext)) {
		if (OSPF6_LSA_IS_MAXAGE(lsa)) {
			ospf6_increment_retrans_count(lsa);
			ospf6_lsdb_add(ospf6_lsa_copy(lsa), on->retrans_list);
		} else
			ospf6_lsdb_add(ospf6_lsa_copy(lsa), on->summary_list);
	}

	UNSET_FLAG(on->dbdesc_bits, OSPF6_DBDESC_IBIT);
	ospf6_neighbor_state_change(OSPF6_NEIGHBOR_EXCHANGE, on,
				    OSPF6_NEIGHBOR_EVENT_NEGOTIATION_DONE);
}

static void ospf6_neighbor_last_dbdesc_release(struct event *thread)
{
	struct ospf6_neighbor *on = EVENT_ARG(thread);

	assert(on);
	memset(&on->dbdesc_last, 0, sizeof(struct ospf6_dbdesc));
}

void exchange_done(struct event *thread)
{
	struct ospf6_neighbor *on;

	on = (struct ospf6_neighbor *)EVENT_ARG(thread);
	assert(on);

	if (on->state != OSPF6_NEIGHBOR_EXCHANGE)
		return;

	if (IS_OSPF6_DEBUG_NEIGHBOR(EVENT))
		zlog_debug("Neighbor Event %s: *ExchangeDone*", on->name);

	EVENT_OFF(on->thread_send_dbdesc);
	ospf6_lsdb_remove_all(on->dbdesc_list);

	/* RFC 2328 (10.8): Release the last dbdesc after dead_interval */
	if (!CHECK_FLAG(on->dbdesc_bits, OSPF6_DBDESC_MSBIT)) {
		EVENT_OFF(on->last_dbdesc_release_timer);
		event_add_timer(master, ospf6_neighbor_last_dbdesc_release, on,
				on->ospf6_if->dead_interval,
				&on->last_dbdesc_release_timer);
	}

	if (on->request_list->count == 0)
		ospf6_neighbor_state_change(OSPF6_NEIGHBOR_FULL, on,
					    OSPF6_NEIGHBOR_EVENT_EXCHANGE_DONE);
	else {
		ospf6_neighbor_state_change(OSPF6_NEIGHBOR_LOADING, on,
					    OSPF6_NEIGHBOR_EVENT_EXCHANGE_DONE);

		event_add_event(master, ospf6_lsreq_send, on, 0,
				&on->thread_send_lsreq);
	}
}

/* Check loading state. */
void ospf6_check_nbr_loading(struct ospf6_neighbor *on)
{
	/* RFC2328 Section 10.9: When the neighbor responds to these requests
	   with the proper Link State Update packet(s), the Link state request
	   list is truncated and a new Link State Request packet is sent.
	*/
	if ((on->state == OSPF6_NEIGHBOR_LOADING) ||
	    (on->state == OSPF6_NEIGHBOR_EXCHANGE)) {
		if (on->request_list->count == 0)
			event_add_event(master, loading_done, on, 0,
					&on->event_loading_done);
		else if (on->last_ls_req == NULL) {
			EVENT_OFF(on->thread_send_lsreq);
			event_add_event(master, ospf6_lsreq_send, on, 0,
					&on->thread_send_lsreq);
		}
	}
}

void loading_done(struct event *thread)
{
	struct ospf6_neighbor *on;

	on = (struct ospf6_neighbor *)EVENT_ARG(thread);
	assert(on);

	if (on->state != OSPF6_NEIGHBOR_LOADING)
		return;

	if (IS_OSPF6_DEBUG_NEIGHBOR(EVENT))
		zlog_debug("Neighbor Event %s: *LoadingDone*", on->name);

	assert(on->request_list->count == 0);

	ospf6_neighbor_state_change(OSPF6_NEIGHBOR_FULL, on,
				    OSPF6_NEIGHBOR_EVENT_LOADING_DONE);
}

void adj_ok(struct event *thread)
{
	struct ospf6_neighbor *on;

	on = (struct ospf6_neighbor *)EVENT_ARG(thread);
	assert(on);

	if (IS_OSPF6_DEBUG_NEIGHBOR(EVENT))
		zlog_debug("Neighbor Event %s: *AdjOK?*", on->name);

	if (on->state == OSPF6_NEIGHBOR_TWOWAY && need_adjacency(on)) {
		ospf6_neighbor_state_change(OSPF6_NEIGHBOR_EXSTART, on,
					    OSPF6_NEIGHBOR_EVENT_ADJ_OK);
		SET_FLAG(on->dbdesc_bits, OSPF6_DBDESC_MSBIT);
		SET_FLAG(on->dbdesc_bits, OSPF6_DBDESC_MBIT);
		SET_FLAG(on->dbdesc_bits, OSPF6_DBDESC_IBIT);

		EVENT_OFF(on->thread_send_dbdesc);
		event_add_event(master, ospf6_dbdesc_send, on, 0,
				&on->thread_send_dbdesc);

	} else if (on->state >= OSPF6_NEIGHBOR_EXSTART && !need_adjacency(on)) {
		ospf6_neighbor_state_change(OSPF6_NEIGHBOR_TWOWAY, on,
					    OSPF6_NEIGHBOR_EVENT_ADJ_OK);
		ospf6_neighbor_clear_ls_lists(on);
	}
}

void seqnumber_mismatch(struct event *thread)
{
	struct ospf6_neighbor *on;

	on = (struct ospf6_neighbor *)EVENT_ARG(thread);
	assert(on);

	if (on->state < OSPF6_NEIGHBOR_EXCHANGE)
		return;

	if (IS_OSPF6_DEBUG_NEIGHBOR(EVENT))
		zlog_debug("Neighbor Event %s: *SeqNumberMismatch*", on->name);

	ospf6_neighbor_state_change(OSPF6_NEIGHBOR_EXSTART, on,
				    OSPF6_NEIGHBOR_EVENT_SEQNUMBER_MISMATCH);
	SET_FLAG(on->dbdesc_bits, OSPF6_DBDESC_MSBIT);
	SET_FLAG(on->dbdesc_bits, OSPF6_DBDESC_MBIT);
	SET_FLAG(on->dbdesc_bits, OSPF6_DBDESC_IBIT);

	ospf6_neighbor_clear_ls_lists(on);

	EVENT_OFF(on->thread_send_dbdesc);
	on->dbdesc_seqnum++; /* Incr seqnum as per RFC2328, sec 10.3 */

	event_add_event(master, ospf6_dbdesc_send, on, 0,
			&on->thread_send_dbdesc);
}

void bad_lsreq(struct event *thread)
{
	struct ospf6_neighbor *on;

	on = (struct ospf6_neighbor *)EVENT_ARG(thread);
	assert(on);

	if (on->state < OSPF6_NEIGHBOR_EXCHANGE)
		return;

	if (IS_OSPF6_DEBUG_NEIGHBOR(EVENT))
		zlog_debug("Neighbor Event %s: *BadLSReq*", on->name);

	ospf6_neighbor_state_change(OSPF6_NEIGHBOR_EXSTART, on,
				    OSPF6_NEIGHBOR_EVENT_BAD_LSREQ);
	SET_FLAG(on->dbdesc_bits, OSPF6_DBDESC_MSBIT);
	SET_FLAG(on->dbdesc_bits, OSPF6_DBDESC_MBIT);
	SET_FLAG(on->dbdesc_bits, OSPF6_DBDESC_IBIT);

	ospf6_neighbor_clear_ls_lists(on);

	EVENT_OFF(on->thread_send_dbdesc);
	on->dbdesc_seqnum++; /* Incr seqnum as per RFC2328, sec 10.3 */

	event_add_event(master, ospf6_dbdesc_send, on, 0,
			&on->thread_send_dbdesc);
}

void oneway_received(struct event *thread)
{
	struct ospf6_neighbor *on;

	on = (struct ospf6_neighbor *)EVENT_ARG(thread);
	assert(on);

	if (on->state < OSPF6_NEIGHBOR_TWOWAY)
		return;

	if (IS_OSPF6_DEBUG_NEIGHBOR(EVENT))
		zlog_debug("Neighbor Event %s: *1Way-Received*", on->name);

	ospf6_neighbor_state_change(OSPF6_NEIGHBOR_INIT, on,
				    OSPF6_NEIGHBOR_EVENT_ONEWAY_RCVD);
	event_add_event(master, neighbor_change, on->ospf6_if, 0, NULL);

	ospf6_neighbor_clear_ls_lists(on);

	EVENT_OFF(on->thread_send_dbdesc);
	EVENT_OFF(on->thread_send_lsreq);
	EVENT_OFF(on->thread_send_lsupdate);
	EVENT_OFF(on->thread_send_lsack);
	EVENT_OFF(on->thread_exchange_done);
	EVENT_OFF(on->thread_adj_ok);
}

void inactivity_timer(struct event *thread)
{
	struct ospf6_neighbor *on;

	on = (struct ospf6_neighbor *)EVENT_ARG(thread);
	assert(on);

	if (IS_OSPF6_DEBUG_NEIGHBOR(EVENT))
		zlog_debug("Neighbor Event %s: *InactivityTimer*", on->name);

	on->drouter = on->prev_drouter = 0;
	on->bdrouter = on->prev_bdrouter = 0;

	if (!OSPF6_GR_IS_ACTIVE_HELPER(on)) {
		on->drouter = on->prev_drouter = 0;
		on->bdrouter = on->prev_bdrouter = 0;

		ospf6_neighbor_state_change(OSPF6_NEIGHBOR_DOWN, on,
					    OSPF6_NEIGHBOR_EVENT_INACTIVITY_TIMER);
		event_add_event(master, neighbor_change, on->ospf6_if, 0, NULL);

		listnode_delete(on->ospf6_if->neighbor_list, on);
		ospf6_neighbor_delete(on);

	} else {
		if (IS_DEBUG_OSPF6_GR)
			zlog_debug("%s, Acting as HELPER for this neighbour, So restart the dead timer.",
				   __PRETTY_FUNCTION__);

		event_add_timer(master, inactivity_timer, on,
				on->ospf6_if->dead_interval,
				&on->inactivity_timer);
	}
}

/* P2P/P2MP stuff */

uint32_t ospf6_neighbor_cost(struct ospf6_neighbor *on)
{
	if (on->p2xp_cfg && on->p2xp_cfg->cfg_cost)
		return on->p2xp_cfg->cost;
	return on->ospf6_if->cost;
}

static int ospf6_if_p2xp_neighcfg_cmp(const struct ospf6_if_p2xp_neighcfg *a,
				      const struct ospf6_if_p2xp_neighcfg *b)
{
	return IPV6_ADDR_CMP(&a->addr, &b->addr);
}

struct ospf6_if_p2xp_neighcfg *ospf6_if_p2xp_find(struct ospf6_interface *oi,
						  const struct in6_addr *addr)
{
	struct ospf6_if_p2xp_neighcfg ref;

	if (!oi)
		return NULL;

	ref.addr = *addr;
	return ospf6_if_p2xp_neighcfgs_find(&oi->p2xp_neighs, &ref);
}

static struct ospf6_if_p2xp_neighcfg *
ospf6_if_p2xp_get(struct ospf6_interface *oi, const struct in6_addr *addr)
{
	struct ospf6_if_p2xp_neighcfg ref, *ret;

	if (!oi)
		return NULL;

	ref.addr = *addr;
	ret = ospf6_if_p2xp_neighcfgs_find(&oi->p2xp_neighs, &ref);
	if (!ret) {
		ret = XCALLOC(MTYPE_OSPF6_NEIGHBOR_P2XP_CFG, sizeof(*ret));
		ret->addr = *addr;
		ret->ospf6_if = oi;

		ospf6_if_p2xp_neighcfgs_add(&oi->p2xp_neighs, ret);
	}

	return ret;
}

static void ospf6_if_p2xp_destroy(struct ospf6_if_p2xp_neighcfg *p2xp_cfg)
{
	EVENT_OFF(p2xp_cfg->t_unicast_hello);
	ospf6_if_p2xp_neighcfgs_del(&p2xp_cfg->ospf6_if->p2xp_neighs, p2xp_cfg);

	XFREE(MTYPE_OSPF6_NEIGHBOR_P2XP_CFG, p2xp_cfg);
}

static void p2xp_neigh_refresh(struct ospf6_neighbor *on, uint32_t prev_cost)
{
	if (on->p2xp_cfg)
		on->p2xp_cfg->active = NULL;
	on->p2xp_cfg = ospf6_if_p2xp_find(on->ospf6_if, &on->linklocal_addr);
	if (on->p2xp_cfg)
		on->p2xp_cfg->active = on;

	if (ospf6_neighbor_cost(on) != prev_cost)
		OSPF6_ROUTER_LSA_SCHEDULE(on->ospf6_if->area);
}

/* vty functions */

#ifndef VTYSH_EXTRACT_PL
#include "ospf6d/ospf6_neighbor_clippy.c"
#endif

DEFPY (ipv6_ospf6_p2xp_neigh,
       ipv6_ospf6_p2xp_neigh_cmd,
       "[no] ipv6 ospf6 neighbor X:X::X:X",
       NO_STR
       IP6_STR
       OSPF6_STR
       "Configure static neighbor\n"
       "Neighbor link-local address\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct ospf6_interface *oi = ifp->info;
	struct ospf6_if_p2xp_neighcfg *p2xp_cfg;

	if (!oi) {
		if (no)
			return CMD_SUCCESS;
		oi = ospf6_interface_create(ifp);
	}

	if (no) {
		struct ospf6_neighbor *on;
		uint32_t prev_cost = 0;

		p2xp_cfg = ospf6_if_p2xp_find(oi, &neighbor);
		if (!p2xp_cfg)
			return CMD_SUCCESS;

		on = p2xp_cfg->active;
		if (on)
			prev_cost = ospf6_neighbor_cost(on);

		p2xp_cfg->active = NULL;
		ospf6_if_p2xp_destroy(p2xp_cfg);

		if (on) {
			on->p2xp_cfg = NULL;
			p2xp_neigh_refresh(on, prev_cost);
		}
		return CMD_SUCCESS;
	}

	(void)ospf6_if_p2xp_get(oi, &neighbor);
	return CMD_SUCCESS;
}

DEFPY (ipv6_ospf6_p2xp_neigh_cost,
       ipv6_ospf6_p2xp_neigh_cost_cmd,
       "[no] ipv6 ospf6 neighbor X:X::X:X cost (1-65535)",
       NO_STR
       IP6_STR
       OSPF6_STR
       "Configure static neighbor\n"
       "Neighbor link-local address\n"
       "Outgoing metric for this neighbor\n"
       "Outgoing metric for this neighbor\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct ospf6_interface *oi = ifp->info;
	struct ospf6_if_p2xp_neighcfg *p2xp_cfg;
	uint32_t prev_cost = 0;

	if (!oi) {
		if (no)
			return CMD_SUCCESS;
		oi = ospf6_interface_create(ifp);
	}

	p2xp_cfg = ospf6_if_p2xp_get(oi, &neighbor);

	if (p2xp_cfg->active)
		prev_cost = ospf6_neighbor_cost(p2xp_cfg->active);

	if (no) {
		p2xp_cfg->cfg_cost = false;
		p2xp_cfg->cost = 0;
	} else {
		p2xp_cfg->cfg_cost = true;
		p2xp_cfg->cost = cost;
	}

	if (p2xp_cfg->active)
		p2xp_neigh_refresh(p2xp_cfg->active, prev_cost);
	return CMD_SUCCESS;
}

static void p2xp_unicast_hello_send(struct event *event);

static void p2xp_unicast_hello_sched(struct ospf6_if_p2xp_neighcfg *p2xp_cfg)
{
	if (!p2xp_cfg->poll_interval ||
	    (p2xp_cfg->ospf6_if->state != OSPF6_INTERFACE_POINTTOMULTIPOINT &&
	     p2xp_cfg->ospf6_if->state != OSPF6_INTERFACE_POINTTOPOINT))
		/* state check covers DOWN state too */
		EVENT_OFF(p2xp_cfg->t_unicast_hello);
	else
		event_add_timer(master, p2xp_unicast_hello_send, p2xp_cfg,
				p2xp_cfg->poll_interval,
				&p2xp_cfg->t_unicast_hello);
}

void ospf6_if_p2xp_up(struct ospf6_interface *oi)
{
	struct ospf6_if_p2xp_neighcfg *p2xp_cfg;

	frr_each (ospf6_if_p2xp_neighcfgs, &oi->p2xp_neighs, p2xp_cfg)
		p2xp_unicast_hello_sched(p2xp_cfg);
}

static void p2xp_unicast_hello_send(struct event *event)
{
	struct ospf6_if_p2xp_neighcfg *p2xp_cfg = EVENT_ARG(event);
	struct ospf6_interface *oi = p2xp_cfg->ospf6_if;

	if (oi->state != OSPF6_INTERFACE_POINTTOPOINT &&
	    oi->state != OSPF6_INTERFACE_POINTTOMULTIPOINT)
		return;

	p2xp_unicast_hello_sched(p2xp_cfg);

	if (p2xp_cfg->active && p2xp_cfg->active->state >= OSPF6_NEIGHBOR_INIT)
		return;

	ospf6_hello_send_addr(oi, &p2xp_cfg->addr);
}

DEFPY (ipv6_ospf6_p2xp_neigh_poll_interval,
       ipv6_ospf6_p2xp_neigh_poll_interval_cmd,
       "[no] ipv6 ospf6 neighbor X:X::X:X poll-interval (1-65535)",
       NO_STR
       IP6_STR
       OSPF6_STR
       "Configure static neighbor\n"
       "Neighbor link-local address\n"
       "Send unicast hellos to neighbor when down\n"
       "Unicast hello interval when down (seconds)\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct ospf6_interface *oi = ifp->info;
	struct ospf6_if_p2xp_neighcfg *p2xp_cfg;

	if (!oi) {
		if (no)
			return CMD_SUCCESS;
		oi = ospf6_interface_create(ifp);
	}
	if (no)
		poll_interval = 0;

	p2xp_cfg = ospf6_if_p2xp_get(oi, &neighbor);
	p2xp_cfg->poll_interval = poll_interval;

	p2xp_unicast_hello_sched(p2xp_cfg);
	return CMD_SUCCESS;
}

/* show neighbor structure */
static void ospf6_neighbor_show(struct vty *vty, struct ospf6_neighbor *on,
				json_object *json_array, bool use_json)
{
	char router_id[16];
	char duration[64];
	struct timeval res;
	char nstate[16];
	char deadtime[64];
	long h, m, s;
	json_object *json_route;

	/* Router-ID (Name) */
	inet_ntop(AF_INET, &on->router_id, router_id, sizeof(router_id));
#ifdef HAVE_GETNAMEINFO
	{
	}
#endif /*HAVE_GETNAMEINFO*/

	/* Dead time */
	h = m = s = 0;
	if (on->inactivity_timer) {
		s = monotime_until(&on->inactivity_timer->u.sands, NULL) /
		    1000000LL;
		h = s / 3600;
		s -= h * 3600;
		m = s / 60;
		s -= m * 60;
	}
	snprintf(deadtime, sizeof(deadtime), "%02ld:%02ld:%02ld", h, m, s);

	/* Neighbor State */
	if (on->ospf6_if->type == OSPF_IFTYPE_POINTOPOINT)
		snprintf(nstate, sizeof(nstate), "PointToPoint");
	else if (on->ospf6_if->type == OSPF_IFTYPE_POINTOMULTIPOINT)
		snprintf(nstate, sizeof(nstate), "PtMultipoint");
	else {
		if (on->router_id == on->drouter)
			snprintf(nstate, sizeof(nstate), "DR");
		else if (on->router_id == on->bdrouter)
			snprintf(nstate, sizeof(nstate), "BDR");
		else
			snprintf(nstate, sizeof(nstate), "DROther");
	}

	/* Duration */
	monotime_since(&on->last_changed, &res);
	timerstring(&res, duration, sizeof(duration));

	/*
	vty_out (vty, "%-15s %3d %11s %6s/%-12s %11s %s[%s]\n",
		 "Neighbor ID", "Pri", "DeadTime", "State", "IfState",
	"Duration", "I/F", "State");
	*/
	if (use_json) {
		json_route = json_object_new_object();

		json_object_string_add(json_route, "neighborId", router_id);
		json_object_int_add(json_route, "priority", on->priority);
		json_object_string_add(json_route, "deadTime", deadtime);
		json_object_string_add(json_route, "state",
				       ospf6_neighbor_state_str[on->state]);
		json_object_string_add(json_route, "ifState", nstate);
		json_object_string_add(json_route, "duration", duration);
		json_object_string_add(json_route, "interfaceName",
				       on->ospf6_if->interface->name);
		json_object_string_add(json_route, "interfaceState",
				       ospf6_interface_state_str
					       [on->ospf6_if->state]);

		json_object_array_add(json_array, json_route);
	} else
		vty_out(vty, "%-15s %3d %11s %8s/%-12s %11s %s[%s]\n",
			router_id, on->priority, deadtime,
			ospf6_neighbor_state_str[on->state], nstate, duration,
			on->ospf6_if->interface->name,
			ospf6_interface_state_str[on->ospf6_if->state]);
}

static void ospf6_neighbor_show_drchoice(struct vty *vty,
					 struct ospf6_neighbor *on,
					 json_object *json_array, bool use_json)
{
	char router_id[16];
	char drouter[16], bdrouter[16];
	char duration[64];
	struct timeval now, res;
	json_object *json_route;

	/*
	    vty_out (vty, "%-15s %6s/%-11s %-15s %-15s %s[%s]\n",
		     "RouterID", "State", "Duration", "DR", "BDR", "I/F",
		     "State");
	*/

	inet_ntop(AF_INET, &on->router_id, router_id, sizeof(router_id));
	inet_ntop(AF_INET, &on->drouter, drouter, sizeof(drouter));
	inet_ntop(AF_INET, &on->bdrouter, bdrouter, sizeof(bdrouter));

	monotime(&now);
	timersub(&now, &on->last_changed, &res);
	timerstring(&res, duration, sizeof(duration));

	if (use_json) {
		json_route = json_object_new_object();
		json_object_string_add(json_route, "routerId", router_id);
		json_object_string_add(json_route, "state",
				       ospf6_neighbor_state_str[on->state]);
		json_object_string_add(json_route, "duration", duration);
		json_object_string_add(json_route, "dRouter", drouter);
		json_object_string_add(json_route, "bdRouter", bdrouter);
		json_object_string_add(json_route, "interfaceName",
				       on->ospf6_if->interface->name);
		json_object_string_add(json_route, "interfaceState",
				       ospf6_interface_state_str
					       [on->ospf6_if->state]);

		json_object_array_add(json_array, json_route);
	} else
		vty_out(vty, "%-15s %8s/%-11s %-15s %-15s %s[%s]\n", router_id,
			ospf6_neighbor_state_str[on->state], duration, drouter,
			bdrouter, on->ospf6_if->interface->name,
			ospf6_interface_state_str[on->ospf6_if->state]);
}

static void ospf6_neighbor_show_detail(struct vty *vty,
				       struct ospf6_neighbor *on,
				       json_object *json, bool use_json)
{
	char drouter[16], bdrouter[16];
	char linklocal_addr[64], duration[32];
	struct timeval now, res;
	struct ospf6_lsa *lsa, *lsanext;
	json_object *json_neighbor;
	json_object *json_array;
	char db_desc_str[20];

	inet_ntop(AF_INET6, &on->linklocal_addr, linklocal_addr,
		  sizeof(linklocal_addr));
	inet_ntop(AF_INET, &on->drouter, drouter, sizeof(drouter));
	inet_ntop(AF_INET, &on->bdrouter, bdrouter, sizeof(bdrouter));

	monotime(&now);
	timersub(&now, &on->last_changed, &res);
	timerstring(&res, duration, sizeof(duration));

	if (use_json) {
		json_neighbor = json_object_new_object();
		json_object_string_add(json_neighbor, "area",
				       on->ospf6_if->area->name);
		json_object_string_add(json_neighbor, "interface",
				       on->ospf6_if->interface->name);
		json_object_int_add(json_neighbor, "interfaceIndex",
				    on->ospf6_if->interface->ifindex);
		json_object_int_add(json_neighbor, "neighborInterfaceIndex",
				    on->ifindex);
		json_object_string_addf(json_neighbor, "localLinkLocalAddress",
				       "%pI6", on->ospf6_if->linklocal_addr);
		json_object_string_add(json_neighbor, "linkLocalAddress",
				       linklocal_addr);
		json_object_string_add(json_neighbor, "neighborState",
				       ospf6_neighbor_state_str[on->state]);
		json_object_string_add(json_neighbor, "neighborStateDuration",
				       duration);
		json_object_string_add(json_neighbor, "neighborDRouter",
				       drouter);
		json_object_string_add(json_neighbor, "neighborBdRouter",
				       bdrouter);
		snprintf(db_desc_str, sizeof(db_desc_str), "%s%s%s",
			 (CHECK_FLAG(on->dbdesc_bits, OSPF6_DBDESC_IBIT)
				  ? "Initial "
				  : ""),
			 (CHECK_FLAG(on->dbdesc_bits, OSPF6_DBDESC_MBIT) ? "More"
									 : ""),
			 (CHECK_FLAG(on->dbdesc_bits, OSPF6_DBDESC_MSBIT)
				  ? "Master"
				  : "Slave"));
		json_object_string_add(json_neighbor, "dbDescStatus",
				       db_desc_str);

		json_object_int_add(json_neighbor, "dbDescSeqNumber",
				    (unsigned long)ntohl(on->dbdesc_seqnum));

		json_array = json_object_new_array();
		json_object_int_add(json_neighbor, "summaryListCount",
				    on->summary_list->count);
		for (ALL_LSDB(on->summary_list, lsa, lsanext))
			json_object_array_add(json_array,
					      json_object_new_string(lsa->name));
		json_object_object_add(json_neighbor, "summaryListLsa",
				       json_array);

		json_array = json_object_new_array();
		json_object_int_add(json_neighbor, "requestListCount",
				    on->request_list->count);
		for (ALL_LSDB(on->request_list, lsa, lsanext))
			json_object_array_add(json_array,
					      json_object_new_string(lsa->name));
		json_object_object_add(json_neighbor, "requestListLsa",
				       json_array);

		json_array = json_object_new_array();
		json_object_int_add(json_neighbor, "reTransListCount",
				    on->retrans_list->count);
		for (ALL_LSDB(on->retrans_list, lsa, lsanext))
			json_object_array_add(json_array,
					      json_object_new_string(lsa->name));
		json_object_object_add(json_neighbor, "reTransListLsa",
				       json_array);


		timerclear(&res);
		if (event_is_scheduled(on->thread_send_dbdesc))
			timersub(&on->thread_send_dbdesc->u.sands, &now, &res);
		timerstring(&res, duration, sizeof(duration));
		json_object_int_add(json_neighbor, "pendingLsaDbDescCount",
				    on->dbdesc_list->count);
		json_object_string_add(json_neighbor, "pendingLsaDbDescTime",
				       duration);
		json_object_string_add(json_neighbor, "dbDescSendThread",
				       (event_is_scheduled(on->thread_send_dbdesc)
						? "on"
						: "off"));
		json_array = json_object_new_array();
		for (ALL_LSDB(on->dbdesc_list, lsa, lsanext))
			json_object_array_add(json_array,
					      json_object_new_string(lsa->name));
		json_object_object_add(json_neighbor, "pendingLsaDbDesc",
				       json_array);

		timerclear(&res);
		if (event_is_scheduled(on->thread_send_lsreq))
			timersub(&on->thread_send_lsreq->u.sands, &now, &res);
		timerstring(&res, duration, sizeof(duration));
		json_object_int_add(json_neighbor, "pendingLsaLsReqCount",
				    on->request_list->count);
		json_object_string_add(json_neighbor, "pendingLsaLsReqTime",
				       duration);
		json_object_string_add(json_neighbor, "lsReqSendThread",
				       (event_is_scheduled(on->thread_send_lsreq)
						? "on"
						: "off"));
		json_array = json_object_new_array();
		for (ALL_LSDB(on->request_list, lsa, lsanext))
			json_object_array_add(json_array,
					      json_object_new_string(lsa->name));
		json_object_object_add(json_neighbor, "pendingLsaLsReq",
				       json_array);


		timerclear(&res);
		if (event_is_scheduled(on->thread_send_lsupdate))
			timersub(&on->thread_send_lsupdate->u.sands, &now, &res);
		timerstring(&res, duration, sizeof(duration));
		json_object_int_add(json_neighbor, "pendingLsaLsUpdateCount",
				    on->lsupdate_list->count);
		json_object_string_add(json_neighbor, "pendingLsaLsUpdateTime",
				       duration);
		json_object_string_add(json_neighbor, "lsUpdateSendThread",
				       (event_is_scheduled(
						on->thread_send_lsupdate)
						? "on"
						: "off"));
		json_array = json_object_new_array();
		for (ALL_LSDB(on->lsupdate_list, lsa, lsanext))
			json_object_array_add(json_array,
					      json_object_new_string(lsa->name));
		json_object_object_add(json_neighbor, "pendingLsaLsUpdate",
				       json_array);

		timerclear(&res);
		if (event_is_scheduled(on->thread_send_lsack))
			timersub(&on->thread_send_lsack->u.sands, &now, &res);
		timerstring(&res, duration, sizeof(duration));
		json_object_int_add(json_neighbor, "pendingLsaLsAckCount",
				    on->lsack_list->count);
		json_object_string_add(json_neighbor, "pendingLsaLsAckTime",
				       duration);
		json_object_string_add(json_neighbor, "lsAckSendThread",
				       (event_is_scheduled(on->thread_send_lsack)
						? "on"
						: "off"));
		json_array = json_object_new_array();
		for (ALL_LSDB(on->lsack_list, lsa, lsanext))
			json_object_array_add(json_array,
					      json_object_new_string(lsa->name));
		json_object_object_add(json_neighbor, "pendingLsaLsAck",
				       json_array);

		bfd_sess_show(vty, json_neighbor, on->bfd_session);

		if (on->auth_present == true) {
			json_object_string_add(json_neighbor, "authStatus",
					       "enabled");
			json_object_int_add(json_neighbor,
					    "recvdHelloHigherSeqNo",
					    on->seqnum_h[OSPF6_MESSAGE_TYPE_HELLO]);
			json_object_int_add(json_neighbor,
					    "recvdHelloLowerSeqNo",
					    on->seqnum_l[OSPF6_MESSAGE_TYPE_HELLO]);
			json_object_int_add(json_neighbor,
					    "recvdDBDescHigherSeqNo",
					    on->seqnum_h[OSPF6_MESSAGE_TYPE_DBDESC]);
			json_object_int_add(json_neighbor,
					    "recvdDBDescLowerSeqNo",
					    on->seqnum_l[OSPF6_MESSAGE_TYPE_DBDESC]);
			json_object_int_add(json_neighbor,
					    "recvdLSReqHigherSeqNo",
					    on->seqnum_h[OSPF6_MESSAGE_TYPE_LSREQ]);
			json_object_int_add(json_neighbor,
					    "recvdLSReqLowerSeqNo",
					    on->seqnum_l[OSPF6_MESSAGE_TYPE_LSREQ]);
			json_object_int_add(json_neighbor,
					    "recvdLSUpdHigherSeqNo",
					    on->seqnum_h[OSPF6_MESSAGE_TYPE_LSUPDATE]);
			json_object_int_add(json_neighbor,
					    "recvdLSUpdLowerSeqNo",
					    on->seqnum_l[OSPF6_MESSAGE_TYPE_LSUPDATE]);
			json_object_int_add(json_neighbor,
					    "recvdLSAckHigherSeqNo",
					    on->seqnum_h[OSPF6_MESSAGE_TYPE_LSACK]);
			json_object_int_add(json_neighbor,
					    "recvdLSAckLowerSeqNo",
					    on->seqnum_l[OSPF6_MESSAGE_TYPE_LSACK]);
		} else
			json_object_string_add(json_neighbor, "authStatus",
					       "disabled");

		json_object_object_add(json, on->name, json_neighbor);

	} else {
		vty_out(vty, " Neighbor %s\n", on->name);
		vty_out(vty, "    Area %s via interface %s (ifindex %d)\n",
			on->ospf6_if->area->name, on->ospf6_if->interface->name,
			on->ospf6_if->interface->ifindex);
		vty_out(vty, "    His IfIndex: %d Link-local address: %s\n",
			on->ifindex, linklocal_addr);
		vty_out(vty, "    State %s for a duration of %s\n",
			ospf6_neighbor_state_str[on->state], duration);
		vty_out(vty, "    His choice of DR/BDR %s/%s, Priority %d\n",
			drouter, bdrouter, on->priority);
		vty_out(vty, "    DbDesc status: %s%s%s SeqNum: %#lx\n",
			(CHECK_FLAG(on->dbdesc_bits, OSPF6_DBDESC_IBIT)
				 ? "Initial "
				 : ""),
			(CHECK_FLAG(on->dbdesc_bits, OSPF6_DBDESC_MBIT) ? "More "
									: ""),
			(CHECK_FLAG(on->dbdesc_bits, OSPF6_DBDESC_MSBIT)
				 ? "Master"
				 : "Slave"),
			(unsigned long)ntohl(on->dbdesc_seqnum));

		vty_out(vty, "    Summary-List: %d LSAs\n",
			on->summary_list->count);
		for (ALL_LSDB(on->summary_list, lsa, lsanext))
			vty_out(vty, "      %s\n", lsa->name);

		vty_out(vty, "    Request-List: %d LSAs\n",
			on->request_list->count);
		for (ALL_LSDB(on->request_list, lsa, lsanext))
			vty_out(vty, "      %s\n", lsa->name);

		vty_out(vty, "    Retrans-List: %d LSAs\n",
			on->retrans_list->count);
		for (ALL_LSDB(on->retrans_list, lsa, lsanext))
			vty_out(vty, "      %s\n", lsa->name);

		timerclear(&res);
		if (event_is_scheduled(on->thread_send_dbdesc))
			timersub(&on->thread_send_dbdesc->u.sands, &now, &res);
		timerstring(&res, duration, sizeof(duration));
		vty_out(vty,
			"    %d Pending LSAs for DbDesc in Time %s [thread %s]\n",
			on->dbdesc_list->count, duration,
			(event_is_scheduled(on->thread_send_dbdesc) ? "on"
								    : "off"));
		for (ALL_LSDB(on->dbdesc_list, lsa, lsanext))
			vty_out(vty, "      %s\n", lsa->name);

		timerclear(&res);
		if (event_is_scheduled(on->thread_send_lsreq))
			timersub(&on->thread_send_lsreq->u.sands, &now, &res);
		timerstring(&res, duration, sizeof(duration));
		vty_out(vty,
			"    %d Pending LSAs for LSReq in Time %s [thread %s]\n",
			on->request_list->count, duration,
			(event_is_scheduled(on->thread_send_lsreq) ? "on"
								   : "off"));
		for (ALL_LSDB(on->request_list, lsa, lsanext))
			vty_out(vty, "      %s\n", lsa->name);

		timerclear(&res);
		if (event_is_scheduled(on->thread_send_lsupdate))
			timersub(&on->thread_send_lsupdate->u.sands, &now, &res);
		timerstring(&res, duration, sizeof(duration));
		vty_out(vty,
			"    %d Pending LSAs for LSUpdate in Time %s [thread %s]\n",
			on->lsupdate_list->count, duration,
			(event_is_scheduled(on->thread_send_lsupdate) ? "on"
								      : "off"));
		for (ALL_LSDB(on->lsupdate_list, lsa, lsanext))
			vty_out(vty, "      %s\n", lsa->name);

		timerclear(&res);
		if (event_is_scheduled(on->thread_send_lsack))
			timersub(&on->thread_send_lsack->u.sands, &now, &res);
		timerstring(&res, duration, sizeof(duration));
		vty_out(vty,
			"    %d Pending LSAs for LSAck in Time %s [thread %s]\n",
			on->lsack_list->count, duration,
			(event_is_scheduled(on->thread_send_lsack) ? "on"
								   : "off"));
		for (ALL_LSDB(on->lsack_list, lsa, lsanext))
			vty_out(vty, "      %s\n", lsa->name);

		bfd_sess_show(vty, NULL, on->bfd_session);

		if (on->auth_present == true) {
			vty_out(vty, "    Authentication header present\n");
			vty_out(vty,
				"\t\t\t hello        DBDesc       LSReq        LSUpd        LSAck\n");
			vty_out(vty,
				"      Higher sequence no 0x%-10X 0x%-10X 0x%-10X 0x%-10X 0x%-10X\n",
				on->seqnum_h[OSPF6_MESSAGE_TYPE_HELLO],
				on->seqnum_h[OSPF6_MESSAGE_TYPE_DBDESC],
				on->seqnum_h[OSPF6_MESSAGE_TYPE_LSREQ],
				on->seqnum_h[OSPF6_MESSAGE_TYPE_LSUPDATE],
				on->seqnum_h[OSPF6_MESSAGE_TYPE_LSACK]);
			vty_out(vty,
				"      Lower sequence no  0x%-10X 0x%-10X 0x%-10X 0x%-10X 0x%-10X\n",
				on->seqnum_l[OSPF6_MESSAGE_TYPE_HELLO],
				on->seqnum_l[OSPF6_MESSAGE_TYPE_DBDESC],
				on->seqnum_l[OSPF6_MESSAGE_TYPE_LSREQ],
				on->seqnum_l[OSPF6_MESSAGE_TYPE_LSUPDATE],
				on->seqnum_l[OSPF6_MESSAGE_TYPE_LSACK]);
		} else
			vty_out(vty, "    Authentication header not present\n");
	}
}

static void ospf6_neighbor_show_detail_common(struct vty *vty,
					      struct ospf6 *ospf6, bool uj,
					      bool detail, bool drchoice)
{
	struct ospf6_neighbor *on;
	struct ospf6_interface *oi;
	struct ospf6_area *oa;
	struct listnode *i, *j, *k;
	json_object *json = NULL;
	json_object *json_array = NULL;
	void (*showfunc)(struct vty *, struct ospf6_neighbor *,
			 json_object *json, bool use_json);

	if (detail)
		showfunc = ospf6_neighbor_show_detail;
	else if (drchoice)
		showfunc = ospf6_neighbor_show_drchoice;
	else
		showfunc = ospf6_neighbor_show;

	if (uj) {
		json = json_object_new_object();
		json_array = json_object_new_array();
	} else {
		if (showfunc == ospf6_neighbor_show)
			vty_out(vty, "%-15s %3s %11s %8s/%-12s %11s %s[%s]\n",
				"Neighbor ID", "Pri", "DeadTime", "State",
				"IfState", "Duration", "I/F", "State");
		else if (showfunc == ospf6_neighbor_show_drchoice)
			vty_out(vty, "%-15s %8s/%-11s %-15s %-15s %s[%s]\n",
				"RouterID", "State", "Duration", "DR", "BDR",
				"I/F", "State");
	}

	for (ALL_LIST_ELEMENTS_RO(ospf6->area_list, i, oa))
		for (ALL_LIST_ELEMENTS_RO(oa->if_list, j, oi))
			for (ALL_LIST_ELEMENTS_RO(oi->neighbor_list, k, on)) {
				if (showfunc == ospf6_neighbor_show_detail)
					(*showfunc)(vty, on, json, uj);
				else
					(*showfunc)(vty, on, json_array, uj);
			}

	if (uj) {
		if (showfunc != ospf6_neighbor_show_detail)
			json_object_object_add(json, "neighbors", json_array);
		else
			json_object_free(json_array);
		vty_json(vty, json);
	}
}

DEFUN(show_ipv6_ospf6_neighbor,
      show_ipv6_ospf6_neighbor_cmd,
      "show ipv6 ospf6 [vrf <NAME|all>] neighbor [<detail|drchoice>] [json]",
      SHOW_STR
      IP6_STR
      OSPF6_STR
      VRF_CMD_HELP_STR
      "All VRFs\n"
      "Neighbor list\n"
      "Display details\n"
      "Display DR choices\n"
      JSON_STR)
{
	struct ospf6 *ospf6;
	struct listnode *node;
	const char *vrf_name = NULL;
	bool all_vrf = false;
	int idx_vrf = 0;
	int idx_type = 4;
	bool uj = use_json(argc, argv);
	bool detail = false;
	bool drchoice = false;

	OSPF6_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);

	if (argv_find(argv, argc, "detail", &idx_type))
		detail = true;
	else if (argv_find(argv, argc, "drchoice", &idx_type))
		drchoice = true;

	for (ALL_LIST_ELEMENTS_RO(om6->ospf6, node, ospf6)) {
		if (all_vrf || strcmp(ospf6->name, vrf_name) == 0) {
			ospf6_neighbor_show_detail_common(vty, ospf6, uj,
							  detail, drchoice);
			if (!all_vrf)
				break;
		}
	}

	OSPF6_CMD_CHECK_VRF(uj, all_vrf, ospf6);

	return CMD_SUCCESS;
}

static int ospf6_neighbor_show_common(struct vty *vty, int argc,
				      struct cmd_token **argv,
				      struct ospf6 *ospf6, int idx_ipv4, bool uj)
{
	struct ospf6_neighbor *on;
	struct ospf6_interface *oi;
	struct ospf6_area *oa;
	struct listnode *i, *j, *k;
	void (*showfunc)(struct vty *, struct ospf6_neighbor *,
			 json_object *json, bool use_json);
	uint32_t router_id;
	json_object *json = NULL;

	showfunc = ospf6_neighbor_show_detail;
	if (uj)
		json = json_object_new_object();

	if ((inet_pton(AF_INET, argv[idx_ipv4]->arg, &router_id)) != 1) {
		vty_out(vty, "Router-ID is not parsable: %s\n",
			argv[idx_ipv4]->arg);
		return CMD_SUCCESS;
	}

	for (ALL_LIST_ELEMENTS_RO(ospf6->area_list, i, oa))
		for (ALL_LIST_ELEMENTS_RO(oa->if_list, j, oi))
			for (ALL_LIST_ELEMENTS_RO(oi->neighbor_list, k, on)) {
				if (router_id == on->router_id)
					(*showfunc)(vty, on, json, uj);
			}

	if (uj)
		vty_json(vty, json);

	return CMD_SUCCESS;
}

DEFUN(show_ipv6_ospf6_neighbor_one,
      show_ipv6_ospf6_neighbor_one_cmd,
      "show ipv6 ospf6 [vrf <NAME|all>] neighbor A.B.C.D [json]",
      SHOW_STR
      IP6_STR
      OSPF6_STR
      VRF_CMD_HELP_STR
      "All VRFs\n"
      "Neighbor list\n"
      "Specify Router-ID as IPv4 address notation\n"
      JSON_STR)
{
	int idx_ipv4 = 4;
	struct ospf6 *ospf6;
	struct listnode *node;
	const char *vrf_name = NULL;
	bool all_vrf = false;
	int idx_vrf = 0;
	bool uj = use_json(argc, argv);

	OSPF6_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);
	if (idx_vrf > 0)
		idx_ipv4 += 2;

	for (ALL_LIST_ELEMENTS_RO(om6->ospf6, node, ospf6)) {
		if (all_vrf || strcmp(ospf6->name, vrf_name) == 0) {
			ospf6_neighbor_show_common(vty, argc, argv, ospf6,
						   idx_ipv4, uj);

			if (!all_vrf)
				break;
		}
	}

	OSPF6_CMD_CHECK_VRF(uj, all_vrf, ospf6);

	return CMD_SUCCESS;
}

void ospf6_neighbor_init(void)
{
	install_element(VIEW_NODE, &show_ipv6_ospf6_neighbor_cmd);
	install_element(VIEW_NODE, &show_ipv6_ospf6_neighbor_one_cmd);

	install_element(INTERFACE_NODE, &ipv6_ospf6_p2xp_neigh_cmd);
	install_element(INTERFACE_NODE, &ipv6_ospf6_p2xp_neigh_cost_cmd);
	install_element(INTERFACE_NODE,
			&ipv6_ospf6_p2xp_neigh_poll_interval_cmd);
}

DEFUN (debug_ospf6_neighbor,
       debug_ospf6_neighbor_cmd,
       "debug ospf6 neighbor [<state|event>]",
       DEBUG_STR
       OSPF6_STR
       "Debug OSPFv3 Neighbor\n"
       "Debug OSPFv3 Neighbor State Change\n"
       "Debug OSPFv3 Neighbor Event\n")
{
	int idx_type = 3;
	unsigned char level = 0;

	if (argc == 4) {
		if (!strncmp(argv[idx_type]->arg, "s", 1))
			level = OSPF6_DEBUG_NEIGHBOR_STATE;
		else if (!strncmp(argv[idx_type]->arg, "e", 1))
			level = OSPF6_DEBUG_NEIGHBOR_EVENT;
	} else
		level = OSPF6_DEBUG_NEIGHBOR_STATE | OSPF6_DEBUG_NEIGHBOR_EVENT;

	OSPF6_DEBUG_NEIGHBOR_ON(level);
	return CMD_SUCCESS;
}


DEFUN (no_debug_ospf6_neighbor,
       no_debug_ospf6_neighbor_cmd,
       "no debug ospf6 neighbor [<state|event>]",
       NO_STR
       DEBUG_STR
       OSPF6_STR
       "Debug OSPFv3 Neighbor\n"
       "Debug OSPFv3 Neighbor State Change\n"
       "Debug OSPFv3 Neighbor Event\n")
{
	int idx_type = 4;
	unsigned char level = 0;

	if (argc == 5) {
		if (!strncmp(argv[idx_type]->arg, "s", 1))
			level = OSPF6_DEBUG_NEIGHBOR_STATE;
		if (!strncmp(argv[idx_type]->arg, "e", 1))
			level = OSPF6_DEBUG_NEIGHBOR_EVENT;
	} else
		level = OSPF6_DEBUG_NEIGHBOR_STATE | OSPF6_DEBUG_NEIGHBOR_EVENT;

	OSPF6_DEBUG_NEIGHBOR_OFF(level);
	return CMD_SUCCESS;
}


DEFUN (no_debug_ospf6,
       no_debug_ospf6_cmd,
       "no debug ospf6",
       NO_STR
       DEBUG_STR
       OSPF6_STR)
{
	unsigned int i;

	OSPF6_DEBUG_ABR_OFF();
	OSPF6_DEBUG_ASBR_OFF();
	OSPF6_DEBUG_BROUTER_OFF();
	OSPF6_DEBUG_BROUTER_SPECIFIC_ROUTER_OFF();
	OSPF6_DEBUG_BROUTER_SPECIFIC_AREA_OFF();
	OSPF6_DEBUG_FLOODING_OFF();
	OSPF6_DEBUG_INTERFACE_OFF();

	ospf6_lsa_debug_set_all(false);

	for (i = 0; i < 6; i++)
		OSPF6_DEBUG_MESSAGE_OFF(i, OSPF6_DEBUG_NEIGHBOR_STATE |
						   OSPF6_DEBUG_NEIGHBOR_EVENT);

	OSPF6_DEBUG_NEIGHBOR_OFF(OSPF6_DEBUG_NEIGHBOR_STATE |
				 OSPF6_DEBUG_NEIGHBOR_EVENT);
	OSPF6_DEBUG_ROUTE_OFF(OSPF6_DEBUG_ROUTE_TABLE);
	OSPF6_DEBUG_ROUTE_OFF(OSPF6_DEBUG_ROUTE_INTRA);
	OSPF6_DEBUG_ROUTE_OFF(OSPF6_DEBUG_ROUTE_INTER);
	OSPF6_DEBUG_ROUTE_OFF(OSPF6_DEBUG_ROUTE_MEMORY);
	OSPF6_DEBUG_SPF_OFF(OSPF6_DEBUG_SPF_PROCESS);
	OSPF6_DEBUG_SPF_OFF(OSPF6_DEBUG_SPF_TIME);
	OSPF6_DEBUG_SPF_OFF(OSPF6_DEBUG_SPF_DATABASE);
	OSPF6_DEBUG_ZEBRA_OFF(OSPF6_DEBUG_ZEBRA_SEND | OSPF6_DEBUG_ZEBRA_RECV);

	return CMD_SUCCESS;
}

int config_write_ospf6_debug_neighbor(struct vty *vty)
{
	if (IS_OSPF6_DEBUG_NEIGHBOR(STATE) && IS_OSPF6_DEBUG_NEIGHBOR(EVENT))
		vty_out(vty, "debug ospf6 neighbor\n");
	else if (IS_OSPF6_DEBUG_NEIGHBOR(STATE))
		vty_out(vty, "debug ospf6 neighbor state\n");
	else if (IS_OSPF6_DEBUG_NEIGHBOR(EVENT))
		vty_out(vty, "debug ospf6 neighbor event\n");
	return 0;
}

int config_write_ospf6_p2xp_neighbor(struct vty *vty, struct ospf6_interface *oi)
{
	struct ospf6_if_p2xp_neighcfg *p2xp_cfg;

	frr_each (ospf6_if_p2xp_neighcfgs, &oi->p2xp_neighs, p2xp_cfg) {
		vty_out(vty, " ipv6 ospf6 neighbor %pI6\n", &p2xp_cfg->addr);

		if (p2xp_cfg->poll_interval)
			vty_out(vty,
				" ipv6 ospf6 neighbor %pI6 poll-interval %u\n",
				&p2xp_cfg->addr, p2xp_cfg->poll_interval);

		if (p2xp_cfg->cfg_cost)
			vty_out(vty, " ipv6 ospf6 neighbor %pI6 cost %u\n",
				&p2xp_cfg->addr, p2xp_cfg->cost);
	}
	return 0;
}

void install_element_ospf6_debug_neighbor(void)
{
	install_element(ENABLE_NODE, &debug_ospf6_neighbor_cmd);
	install_element(ENABLE_NODE, &no_debug_ospf6_neighbor_cmd);
	install_element(ENABLE_NODE, &no_debug_ospf6_cmd);
	install_element(CONFIG_NODE, &debug_ospf6_neighbor_cmd);
	install_element(CONFIG_NODE, &no_debug_ospf6_neighbor_cmd);
	install_element(CONFIG_NODE, &no_debug_ospf6_cmd);
}
