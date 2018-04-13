/*
 * Copyright (C) 2003 Yasuhiro Ohara
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "log.h"
#include "memory.h"
#include "thread.h"
#include "linklist.h"
#include "vty.h"
#include "command.h"

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

DEFINE_HOOK(ospf6_neighbor_change,
	    (struct ospf6_neighbor * on, int state, int next_state),
	    (on, state, next_state))

unsigned char conf_debug_ospf6_neighbor = 0;

const char *ospf6_neighbor_state_str[] = {
	"None",    "Down",     "Attempt", "Init", "Twoway",
	"ExStart", "ExChange", "Loading", "Full", NULL};

int ospf6_neighbor_cmp(void *va, void *vb)
{
	struct ospf6_neighbor *ona = (struct ospf6_neighbor *)va;
	struct ospf6_neighbor *onb = (struct ospf6_neighbor *)vb;
	return (ntohl(ona->router_id) < ntohl(onb->router_id) ? -1 : 1);
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

/* create ospf6_neighbor */
struct ospf6_neighbor *ospf6_neighbor_create(uint32_t router_id,
					     struct ospf6_interface *oi)
{
	struct ospf6_neighbor *on;
	char buf[16];

	on = (struct ospf6_neighbor *)XMALLOC(MTYPE_OSPF6_NEIGHBOR,
					      sizeof(struct ospf6_neighbor));
	if (on == NULL) {
		zlog_warn("neighbor: malloc failed");
		return NULL;
	}

	memset(on, 0, sizeof(struct ospf6_neighbor));
	inet_ntop(AF_INET, &router_id, buf, sizeof(buf));
	snprintf(on->name, sizeof(on->name), "%s%%%s", buf,
		 oi->interface->name);
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

	listnode_add_sort(oi->neighbor_list, on);

	ospf6_bfd_info_nbr_create(oi, on);
	return on;
}

void ospf6_neighbor_delete(struct ospf6_neighbor *on)
{
	struct ospf6_lsa *lsa;

	ospf6_lsdb_remove_all(on->summary_list);
	ospf6_lsdb_remove_all(on->request_list);
	for (ALL_LSDB(on->retrans_list, lsa)) {
		ospf6_decrement_retrans_count(lsa);
		ospf6_lsdb_remove(lsa, on->retrans_list);
	}

	ospf6_lsdb_remove_all(on->dbdesc_list);
	ospf6_lsdb_remove_all(on->lsupdate_list);
	ospf6_lsdb_remove_all(on->lsack_list);

	ospf6_lsdb_delete(on->summary_list);
	ospf6_lsdb_delete(on->request_list);
	ospf6_lsdb_delete(on->retrans_list);

	ospf6_lsdb_delete(on->dbdesc_list);
	ospf6_lsdb_delete(on->lsupdate_list);
	ospf6_lsdb_delete(on->lsack_list);

	THREAD_OFF(on->inactivity_timer);

	THREAD_OFF(on->thread_send_dbdesc);
	THREAD_OFF(on->thread_send_lsreq);
	THREAD_OFF(on->thread_send_lsupdate);
	THREAD_OFF(on->thread_send_lsack);

	ospf6_bfd_reg_dereg_nbr(on, ZEBRA_BFD_DEST_DEREGISTER);
	XFREE(MTYPE_OSPF6_NEIGHBOR, on);
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
		zlog_debug("Neighbor state change %s: [%s]->[%s] (%s)",
			   on->name, ospf6_neighbor_state_str[prev_state],
			   ospf6_neighbor_state_str[next_state],
			   ospf6_neighbor_event_string(event));
	}

	/* Optionally notify about adjacency changes */
	if (CHECK_FLAG(on->ospf6_if->area->ospf6->config_flags,
		       OSPF6_LOG_ADJACENCY_CHANGES)
	    && (CHECK_FLAG(on->ospf6_if->area->ospf6->config_flags,
			   OSPF6_LOG_ADJACENCY_DETAIL)
		|| (next_state == OSPF6_NEIGHBOR_FULL)
		|| (next_state < prev_state)))
		zlog_notice("AdjChg: Nbr %s: %s -> %s (%s)", on->name,
			    ospf6_neighbor_state_str[prev_state],
			    ospf6_neighbor_state_str[next_state],
			    ospf6_neighbor_event_string(event));

	if (prev_state == OSPF6_NEIGHBOR_FULL
	    || next_state == OSPF6_NEIGHBOR_FULL) {
		OSPF6_ROUTER_LSA_SCHEDULE(on->ospf6_if->area);
		if (on->ospf6_if->state == OSPF6_INTERFACE_DR) {
			OSPF6_NETWORK_LSA_SCHEDULE(on->ospf6_if);
			OSPF6_INTRA_PREFIX_LSA_SCHEDULE_TRANSIT(on->ospf6_if);
		}
		if (next_state == OSPF6_NEIGHBOR_FULL)
			on->ospf6_if->area->intra_prefix_originate = 1;

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

	if ((prev_state == OSPF6_NEIGHBOR_EXCHANGE
	     || prev_state == OSPF6_NEIGHBOR_LOADING)
	    && (next_state != OSPF6_NEIGHBOR_EXCHANGE
		&& next_state != OSPF6_NEIGHBOR_LOADING))
		ospf6_maxage_remove(on->ospf6_if->area->ospf6);

	hook_call(ospf6_neighbor_change, on, next_state, prev_state);
	ospf6_bfd_trigger_event(on, prev_state, next_state);
}

/* RFC2328 section 10.4 */
static int need_adjacency(struct ospf6_neighbor *on)
{
	if (on->ospf6_if->state == OSPF6_INTERFACE_POINTTOPOINT
	    || on->ospf6_if->state == OSPF6_INTERFACE_DR
	    || on->ospf6_if->state == OSPF6_INTERFACE_BDR)
		return 1;

	if (on->ospf6_if->drouter == on->router_id
	    || on->ospf6_if->bdrouter == on->router_id)
		return 1;

	return 0;
}

int hello_received(struct thread *thread)
{
	struct ospf6_neighbor *on;

	on = (struct ospf6_neighbor *)THREAD_ARG(thread);
	assert(on);

	if (IS_OSPF6_DEBUG_NEIGHBOR(EVENT))
		zlog_debug("Neighbor Event %s: *HelloReceived*", on->name);

	/* reset Inactivity Timer */
	THREAD_OFF(on->inactivity_timer);
	on->inactivity_timer = NULL;
	thread_add_timer(master, inactivity_timer, on,
			 on->ospf6_if->dead_interval, &on->inactivity_timer);

	if (on->state <= OSPF6_NEIGHBOR_DOWN)
		ospf6_neighbor_state_change(OSPF6_NEIGHBOR_INIT, on,
					    OSPF6_NEIGHBOR_EVENT_HELLO_RCVD);

	return 0;
}

int twoway_received(struct thread *thread)
{
	struct ospf6_neighbor *on;

	on = (struct ospf6_neighbor *)THREAD_ARG(thread);
	assert(on);

	if (on->state > OSPF6_NEIGHBOR_INIT)
		return 0;

	if (IS_OSPF6_DEBUG_NEIGHBOR(EVENT))
		zlog_debug("Neighbor Event %s: *2Way-Received*", on->name);

	thread_add_event(master, neighbor_change, on->ospf6_if, 0, NULL);

	if (!need_adjacency(on)) {
		ospf6_neighbor_state_change(OSPF6_NEIGHBOR_TWOWAY, on,
					    OSPF6_NEIGHBOR_EVENT_TWOWAY_RCVD);
		return 0;
	}

	ospf6_neighbor_state_change(OSPF6_NEIGHBOR_EXSTART, on,
				    OSPF6_NEIGHBOR_EVENT_TWOWAY_RCVD);
	SET_FLAG(on->dbdesc_bits, OSPF6_DBDESC_MSBIT);
	SET_FLAG(on->dbdesc_bits, OSPF6_DBDESC_MBIT);
	SET_FLAG(on->dbdesc_bits, OSPF6_DBDESC_IBIT);

	THREAD_OFF(on->thread_send_dbdesc);
	on->thread_send_dbdesc = NULL;
	thread_add_event(master, ospf6_dbdesc_send, on, 0,
			 &on->thread_send_dbdesc);

	return 0;
}

int negotiation_done(struct thread *thread)
{
	struct ospf6_neighbor *on;
	struct ospf6_lsa *lsa;

	on = (struct ospf6_neighbor *)THREAD_ARG(thread);
	assert(on);

	if (on->state != OSPF6_NEIGHBOR_EXSTART)
		return 0;

	if (IS_OSPF6_DEBUG_NEIGHBOR(EVENT))
		zlog_debug("Neighbor Event %s: *NegotiationDone*", on->name);

	/* clear ls-list */
	ospf6_lsdb_remove_all(on->summary_list);
	ospf6_lsdb_remove_all(on->request_list);
	for (ALL_LSDB(on->retrans_list, lsa)) {
		ospf6_decrement_retrans_count(lsa);
		ospf6_lsdb_remove(lsa, on->retrans_list);
	}

	/* Interface scoped LSAs */
	for (ALL_LSDB(on->ospf6_if->lsdb, lsa)) {
		if (OSPF6_LSA_IS_MAXAGE(lsa)) {
			ospf6_increment_retrans_count(lsa);
			ospf6_lsdb_add(ospf6_lsa_copy(lsa), on->retrans_list);
		} else
			ospf6_lsdb_add(ospf6_lsa_copy(lsa), on->summary_list);
	}

	/* Area scoped LSAs */
	for (ALL_LSDB(on->ospf6_if->area->lsdb, lsa)) {
		if (OSPF6_LSA_IS_MAXAGE(lsa)) {
			ospf6_increment_retrans_count(lsa);
			ospf6_lsdb_add(ospf6_lsa_copy(lsa), on->retrans_list);
		} else
			ospf6_lsdb_add(ospf6_lsa_copy(lsa), on->summary_list);
	}

	/* AS scoped LSAs */
	for (ALL_LSDB(on->ospf6_if->area->ospf6->lsdb, lsa)) {
		if (OSPF6_LSA_IS_MAXAGE(lsa)) {
			ospf6_increment_retrans_count(lsa);
			ospf6_lsdb_add(ospf6_lsa_copy(lsa), on->retrans_list);
		} else
			ospf6_lsdb_add(ospf6_lsa_copy(lsa), on->summary_list);
	}

	UNSET_FLAG(on->dbdesc_bits, OSPF6_DBDESC_IBIT);
	ospf6_neighbor_state_change(OSPF6_NEIGHBOR_EXCHANGE, on,
				    OSPF6_NEIGHBOR_EVENT_NEGOTIATION_DONE);

	return 0;
}

int exchange_done(struct thread *thread)
{
	struct ospf6_neighbor *on;

	on = (struct ospf6_neighbor *)THREAD_ARG(thread);
	assert(on);

	if (on->state != OSPF6_NEIGHBOR_EXCHANGE)
		return 0;

	if (IS_OSPF6_DEBUG_NEIGHBOR(EVENT))
		zlog_debug("Neighbor Event %s: *ExchangeDone*", on->name);

	THREAD_OFF(on->thread_send_dbdesc);
	ospf6_lsdb_remove_all(on->dbdesc_list);

	/* XXX
	  thread_add_timer (master, ospf6_neighbor_last_dbdesc_release, on,
			    on->ospf6_if->dead_interval);
	*/

	if (on->request_list->count == 0)
		ospf6_neighbor_state_change(OSPF6_NEIGHBOR_FULL, on,
					    OSPF6_NEIGHBOR_EVENT_EXCHANGE_DONE);
	else {
		ospf6_neighbor_state_change(OSPF6_NEIGHBOR_LOADING, on,
					    OSPF6_NEIGHBOR_EVENT_EXCHANGE_DONE);

		thread_add_event(master, ospf6_lsreq_send, on, 0,
				 &on->thread_send_lsreq);
	}

	return 0;
}

/* Check loading state. */
void ospf6_check_nbr_loading(struct ospf6_neighbor *on)
{

	/* RFC2328 Section 10.9: When the neighbor responds to these requests
	   with the proper Link State Update packet(s), the Link state request
	   list is truncated and a new Link State Request packet is sent.
	*/
	if ((on->state == OSPF6_NEIGHBOR_LOADING)
	    || (on->state == OSPF6_NEIGHBOR_EXCHANGE)) {
		if (on->request_list->count == 0)
			thread_add_event(master, loading_done, on, 0, NULL);
		else if (on->last_ls_req == NULL) {
			if (on->thread_send_lsreq != NULL)
				THREAD_OFF(on->thread_send_lsreq);
			on->thread_send_lsreq = NULL;
			thread_add_event(master, ospf6_lsreq_send, on, 0,
					 &on->thread_send_lsreq);
		}
	}
}

int loading_done(struct thread *thread)
{
	struct ospf6_neighbor *on;

	on = (struct ospf6_neighbor *)THREAD_ARG(thread);
	assert(on);

	if (on->state != OSPF6_NEIGHBOR_LOADING)
		return 0;

	if (IS_OSPF6_DEBUG_NEIGHBOR(EVENT))
		zlog_debug("Neighbor Event %s: *LoadingDone*", on->name);

	assert(on->request_list->count == 0);

	ospf6_neighbor_state_change(OSPF6_NEIGHBOR_FULL, on,
				    OSPF6_NEIGHBOR_EVENT_LOADING_DONE);

	return 0;
}

int adj_ok(struct thread *thread)
{
	struct ospf6_neighbor *on;
	struct ospf6_lsa *lsa;

	on = (struct ospf6_neighbor *)THREAD_ARG(thread);
	assert(on);

	if (IS_OSPF6_DEBUG_NEIGHBOR(EVENT))
		zlog_debug("Neighbor Event %s: *AdjOK?*", on->name);

	if (on->state == OSPF6_NEIGHBOR_TWOWAY && need_adjacency(on)) {
		ospf6_neighbor_state_change(OSPF6_NEIGHBOR_EXSTART, on,
					    OSPF6_NEIGHBOR_EVENT_ADJ_OK);
		SET_FLAG(on->dbdesc_bits, OSPF6_DBDESC_MSBIT);
		SET_FLAG(on->dbdesc_bits, OSPF6_DBDESC_MBIT);
		SET_FLAG(on->dbdesc_bits, OSPF6_DBDESC_IBIT);

		THREAD_OFF(on->thread_send_dbdesc);
		on->thread_send_dbdesc = NULL;
		thread_add_event(master, ospf6_dbdesc_send, on, 0,
				 &on->thread_send_dbdesc);

	} else if (on->state >= OSPF6_NEIGHBOR_EXSTART && !need_adjacency(on)) {
		ospf6_neighbor_state_change(OSPF6_NEIGHBOR_TWOWAY, on,
					    OSPF6_NEIGHBOR_EVENT_ADJ_OK);
		ospf6_lsdb_remove_all(on->summary_list);
		ospf6_lsdb_remove_all(on->request_list);
		for (ALL_LSDB(on->retrans_list, lsa)) {
			ospf6_decrement_retrans_count(lsa);
			ospf6_lsdb_remove(lsa, on->retrans_list);
		}
	}

	return 0;
}

int seqnumber_mismatch(struct thread *thread)
{
	struct ospf6_neighbor *on;
	struct ospf6_lsa *lsa;

	on = (struct ospf6_neighbor *)THREAD_ARG(thread);
	assert(on);

	if (on->state < OSPF6_NEIGHBOR_EXCHANGE)
		return 0;

	if (IS_OSPF6_DEBUG_NEIGHBOR(EVENT))
		zlog_debug("Neighbor Event %s: *SeqNumberMismatch*", on->name);

	ospf6_neighbor_state_change(OSPF6_NEIGHBOR_EXSTART, on,
				    OSPF6_NEIGHBOR_EVENT_SEQNUMBER_MISMATCH);
	SET_FLAG(on->dbdesc_bits, OSPF6_DBDESC_MSBIT);
	SET_FLAG(on->dbdesc_bits, OSPF6_DBDESC_MBIT);
	SET_FLAG(on->dbdesc_bits, OSPF6_DBDESC_IBIT);

	ospf6_lsdb_remove_all(on->summary_list);
	ospf6_lsdb_remove_all(on->request_list);
	for (ALL_LSDB(on->retrans_list, lsa)) {
		ospf6_decrement_retrans_count(lsa);
		ospf6_lsdb_remove(lsa, on->retrans_list);
	}

	THREAD_OFF(on->thread_send_dbdesc);
	on->dbdesc_seqnum++; /* Incr seqnum as per RFC2328, sec 10.3 */

	on->thread_send_dbdesc = NULL;
	thread_add_event(master, ospf6_dbdesc_send, on, 0,
			 &on->thread_send_dbdesc);

	return 0;
}

int bad_lsreq(struct thread *thread)
{
	struct ospf6_neighbor *on;
	struct ospf6_lsa *lsa;

	on = (struct ospf6_neighbor *)THREAD_ARG(thread);
	assert(on);

	if (on->state < OSPF6_NEIGHBOR_EXCHANGE)
		return 0;

	if (IS_OSPF6_DEBUG_NEIGHBOR(EVENT))
		zlog_debug("Neighbor Event %s: *BadLSReq*", on->name);

	ospf6_neighbor_state_change(OSPF6_NEIGHBOR_EXSTART, on,
				    OSPF6_NEIGHBOR_EVENT_BAD_LSREQ);
	SET_FLAG(on->dbdesc_bits, OSPF6_DBDESC_MSBIT);
	SET_FLAG(on->dbdesc_bits, OSPF6_DBDESC_MBIT);
	SET_FLAG(on->dbdesc_bits, OSPF6_DBDESC_IBIT);

	ospf6_lsdb_remove_all(on->summary_list);
	ospf6_lsdb_remove_all(on->request_list);
	for (ALL_LSDB(on->retrans_list, lsa)) {
		ospf6_decrement_retrans_count(lsa);
		ospf6_lsdb_remove(lsa, on->retrans_list);
	}

	THREAD_OFF(on->thread_send_dbdesc);
	on->dbdesc_seqnum++; /* Incr seqnum as per RFC2328, sec 10.3 */

	on->thread_send_dbdesc = NULL;
	thread_add_event(master, ospf6_dbdesc_send, on, 0,
			 &on->thread_send_dbdesc);

	return 0;
}

int oneway_received(struct thread *thread)
{
	struct ospf6_neighbor *on;
	struct ospf6_lsa *lsa;

	on = (struct ospf6_neighbor *)THREAD_ARG(thread);
	assert(on);

	if (on->state < OSPF6_NEIGHBOR_TWOWAY)
		return 0;

	if (IS_OSPF6_DEBUG_NEIGHBOR(EVENT))
		zlog_debug("Neighbor Event %s: *1Way-Received*", on->name);

	ospf6_neighbor_state_change(OSPF6_NEIGHBOR_INIT, on,
				    OSPF6_NEIGHBOR_EVENT_ONEWAY_RCVD);
	thread_add_event(master, neighbor_change, on->ospf6_if, 0, NULL);

	ospf6_lsdb_remove_all(on->summary_list);
	ospf6_lsdb_remove_all(on->request_list);
	for (ALL_LSDB(on->retrans_list, lsa)) {
		ospf6_decrement_retrans_count(lsa);
		ospf6_lsdb_remove(lsa, on->retrans_list);
	}

	THREAD_OFF(on->thread_send_dbdesc);
	THREAD_OFF(on->thread_send_lsreq);
	THREAD_OFF(on->thread_send_lsupdate);
	THREAD_OFF(on->thread_send_lsack);

	return 0;
}

int inactivity_timer(struct thread *thread)
{
	struct ospf6_neighbor *on;

	on = (struct ospf6_neighbor *)THREAD_ARG(thread);
	assert(on);

	if (IS_OSPF6_DEBUG_NEIGHBOR(EVENT))
		zlog_debug("Neighbor Event %s: *InactivityTimer*", on->name);

	on->inactivity_timer = NULL;
	on->drouter = on->prev_drouter = 0;
	on->bdrouter = on->prev_bdrouter = 0;

	ospf6_neighbor_state_change(OSPF6_NEIGHBOR_DOWN, on,
				    OSPF6_NEIGHBOR_EVENT_INACTIVITY_TIMER);
	thread_add_event(master, neighbor_change, on->ospf6_if, 0, NULL);

	listnode_delete(on->ospf6_if->neighbor_list, on);
	ospf6_neighbor_delete(on);

	return 0;
}


/* vty functions */
/* show neighbor structure */
static void ospf6_neighbor_show(struct vty *vty, struct ospf6_neighbor *on)
{
	char router_id[16];
	char duration[64];
	struct timeval res;
	char nstate[16];
	char deadtime[64];
	long h, m, s;

	/* Router-ID (Name) */
	inet_ntop(AF_INET, &on->router_id, router_id, sizeof(router_id));
#ifdef HAVE_GETNAMEINFO
	{
	}
#endif /*HAVE_GETNAMEINFO*/

	/* Dead time */
	h = m = s = 0;
	if (on->inactivity_timer) {
		s = monotime_until(&on->inactivity_timer->u.sands, NULL)
		    / 1000000LL;
		h = s / 3600;
		s -= h * 3600;
		m = s / 60;
		s -= m * 60;
	}
	snprintf(deadtime, sizeof(deadtime), "%02ld:%02ld:%02ld", h, m, s);

	/* Neighbor State */
	if (if_is_pointopoint(on->ospf6_if->interface))
		snprintf(nstate, sizeof(nstate), "PointToPoint");
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
		 "Neighbor ID", "Pri", "DeadTime", "State", "", "Duration",
		 "I/F", "State");
	*/

	vty_out(vty, "%-15s %3d %11s %8s/%-12s %11s %s[%s]\n", router_id,
		on->priority, deadtime, ospf6_neighbor_state_str[on->state],
		nstate, duration, on->ospf6_if->interface->name,
		ospf6_interface_state_str[on->ospf6_if->state]);
}

static void ospf6_neighbor_show_drchoice(struct vty *vty,
					 struct ospf6_neighbor *on)
{
	char router_id[16];
	char drouter[16], bdrouter[16];
	char duration[64];
	struct timeval now, res;

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

	vty_out(vty, "%-15s %8s/%-11s %-15s %-15s %s[%s]\n", router_id,
		ospf6_neighbor_state_str[on->state], duration, drouter,
		bdrouter, on->ospf6_if->interface->name,
		ospf6_interface_state_str[on->ospf6_if->state]);
}

static void ospf6_neighbor_show_detail(struct vty *vty,
				       struct ospf6_neighbor *on)
{
	char drouter[16], bdrouter[16];
	char linklocal_addr[64], duration[32];
	struct timeval now, res;
	struct ospf6_lsa *lsa;

	inet_ntop(AF_INET6, &on->linklocal_addr, linklocal_addr,
		  sizeof(linklocal_addr));
	inet_ntop(AF_INET, &on->drouter, drouter, sizeof(drouter));
	inet_ntop(AF_INET, &on->bdrouter, bdrouter, sizeof(bdrouter));

	monotime(&now);
	timersub(&now, &on->last_changed, &res);
	timerstring(&res, duration, sizeof(duration));

	vty_out(vty, " Neighbor %s\n", on->name);
	vty_out(vty, "    Area %s via interface %s (ifindex %d)\n",
		on->ospf6_if->area->name, on->ospf6_if->interface->name,
		on->ospf6_if->interface->ifindex);
	vty_out(vty, "    His IfIndex: %d Link-local address: %s\n",
		on->ifindex, linklocal_addr);
	vty_out(vty, "    State %s for a duration of %s\n",
		ospf6_neighbor_state_str[on->state], duration);
	vty_out(vty, "    His choice of DR/BDR %s/%s, Priority %d\n", drouter,
		bdrouter, on->priority);
	vty_out(vty, "    DbDesc status: %s%s%s SeqNum: %#lx\n",
		(CHECK_FLAG(on->dbdesc_bits, OSPF6_DBDESC_IBIT) ? "Initial "
								: ""),
		(CHECK_FLAG(on->dbdesc_bits, OSPF6_DBDESC_MBIT) ? "More " : ""),
		(CHECK_FLAG(on->dbdesc_bits, OSPF6_DBDESC_MSBIT) ? "Master"
								 : "Slave"),
		(unsigned long)ntohl(on->dbdesc_seqnum));

	vty_out(vty, "    Summary-List: %d LSAs\n", on->summary_list->count);
	for (ALL_LSDB(on->summary_list, lsa))
		vty_out(vty, "      %s\n", lsa->name);

	vty_out(vty, "    Request-List: %d LSAs\n", on->request_list->count);
	for (ALL_LSDB(on->request_list, lsa))
		vty_out(vty, "      %s\n", lsa->name);

	vty_out(vty, "    Retrans-List: %d LSAs\n", on->retrans_list->count);
	for (ALL_LSDB(on->retrans_list, lsa))
		vty_out(vty, "      %s\n", lsa->name);

	timerclear(&res);
	if (on->thread_send_dbdesc)
		timersub(&on->thread_send_dbdesc->u.sands, &now, &res);
	timerstring(&res, duration, sizeof(duration));
	vty_out(vty, "    %d Pending LSAs for DbDesc in Time %s [thread %s]\n",
		on->dbdesc_list->count, duration,
		(on->thread_send_dbdesc ? "on" : "off"));
	for (ALL_LSDB(on->dbdesc_list, lsa))
		vty_out(vty, "      %s\n", lsa->name);

	timerclear(&res);
	if (on->thread_send_lsreq)
		timersub(&on->thread_send_lsreq->u.sands, &now, &res);
	timerstring(&res, duration, sizeof(duration));
	vty_out(vty, "    %d Pending LSAs for LSReq in Time %s [thread %s]\n",
		on->request_list->count, duration,
		(on->thread_send_lsreq ? "on" : "off"));
	for (ALL_LSDB(on->request_list, lsa))
		vty_out(vty, "      %s\n", lsa->name);

	timerclear(&res);
	if (on->thread_send_lsupdate)
		timersub(&on->thread_send_lsupdate->u.sands, &now, &res);
	timerstring(&res, duration, sizeof(duration));
	vty_out(vty,
		"    %d Pending LSAs for LSUpdate in Time %s [thread %s]\n",
		on->lsupdate_list->count, duration,
		(on->thread_send_lsupdate ? "on" : "off"));
	for (ALL_LSDB(on->lsupdate_list, lsa))
		vty_out(vty, "      %s\n", lsa->name);

	timerclear(&res);
	if (on->thread_send_lsack)
		timersub(&on->thread_send_lsack->u.sands, &now, &res);
	timerstring(&res, duration, sizeof(duration));
	vty_out(vty, "    %d Pending LSAs for LSAck in Time %s [thread %s]\n",
		on->lsack_list->count, duration,
		(on->thread_send_lsack ? "on" : "off"));
	for (ALL_LSDB(on->lsack_list, lsa))
		vty_out(vty, "      %s\n", lsa->name);

	ospf6_bfd_show_info(vty, on->bfd_info, 0);
}

DEFUN (show_ipv6_ospf6_neighbor,
       show_ipv6_ospf6_neighbor_cmd,
       "show ipv6 ospf6 neighbor [<detail|drchoice>]",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Neighbor list\n"
       "Display details\n"
       "Display DR choices\n")
{
	int idx_type = 4;
	struct ospf6_neighbor *on;
	struct ospf6_interface *oi;
	struct ospf6_area *oa;
	struct listnode *i, *j, *k;
	void (*showfunc)(struct vty *, struct ospf6_neighbor *);

	OSPF6_CMD_CHECK_RUNNING();
	showfunc = ospf6_neighbor_show;

	if (argc == 5) {
		if (!strncmp(argv[idx_type]->arg, "de", 2))
			showfunc = ospf6_neighbor_show_detail;
		else if (!strncmp(argv[idx_type]->arg, "dr", 2))
			showfunc = ospf6_neighbor_show_drchoice;
	}

	if (showfunc == ospf6_neighbor_show)
		vty_out(vty, "%-15s %3s %11s %8s/%-12s %11s %s[%s]\n",
			"Neighbor ID", "Pri", "DeadTime", "State", "IfState",
			"Duration", "I/F", "State");
	else if (showfunc == ospf6_neighbor_show_drchoice)
		vty_out(vty, "%-15s %8s/%-11s %-15s %-15s %s[%s]\n", "RouterID",
			"State", "Duration", "DR", "BDR", "I/F", "State");

	for (ALL_LIST_ELEMENTS_RO(ospf6->area_list, i, oa))
		for (ALL_LIST_ELEMENTS_RO(oa->if_list, j, oi))
			for (ALL_LIST_ELEMENTS_RO(oi->neighbor_list, k, on))
				(*showfunc)(vty, on);

	return CMD_SUCCESS;
}


DEFUN (show_ipv6_ospf6_neighbor_one,
       show_ipv6_ospf6_neighbor_one_cmd,
       "show ipv6 ospf6 neighbor A.B.C.D",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Neighbor list\n"
       "Specify Router-ID as IPv4 address notation\n"
      )
{
	int idx_ipv4 = 4;
	struct ospf6_neighbor *on;
	struct ospf6_interface *oi;
	struct ospf6_area *oa;
	struct listnode *i, *j, *k;
	void (*showfunc)(struct vty *, struct ospf6_neighbor *);
	uint32_t router_id;

	OSPF6_CMD_CHECK_RUNNING();
	showfunc = ospf6_neighbor_show_detail;

	if ((inet_pton(AF_INET, argv[idx_ipv4]->arg, &router_id)) != 1) {
		vty_out(vty, "Router-ID is not parsable: %s\n",
			argv[idx_ipv4]->arg);
		return CMD_SUCCESS;
	}

	for (ALL_LIST_ELEMENTS_RO(ospf6->area_list, i, oa))
		for (ALL_LIST_ELEMENTS_RO(oa->if_list, j, oi))
			for (ALL_LIST_ELEMENTS_RO(oi->neighbor_list, k, on))
				(*showfunc)(vty, on);

	return CMD_SUCCESS;
}

void ospf6_neighbor_init(void)
{
	install_element(VIEW_NODE, &show_ipv6_ospf6_neighbor_cmd);
	install_element(VIEW_NODE, &show_ipv6_ospf6_neighbor_one_cmd);
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
	struct ospf6_lsa_handler *handler = NULL;

	OSPF6_DEBUG_ABR_OFF();
	OSPF6_DEBUG_ASBR_OFF();
	OSPF6_DEBUG_BROUTER_OFF();
	OSPF6_DEBUG_BROUTER_SPECIFIC_ROUTER_OFF();
	OSPF6_DEBUG_BROUTER_SPECIFIC_AREA_OFF();
	OSPF6_DEBUG_FLOODING_OFF();
	OSPF6_DEBUG_INTERFACE_OFF();

	for (i = 0; i < vector_active(ospf6_lsa_handler_vector); i++) {
		handler = vector_slot(ospf6_lsa_handler_vector, i);

		if (handler != NULL) {
			UNSET_FLAG(handler->debug, OSPF6_LSA_DEBUG);
		}
	}

	for (i = 0; i < 6; i++)
		OSPF6_DEBUG_MESSAGE_OFF(i,
					OSPF6_DEBUG_NEIGHBOR_STATE
						| OSPF6_DEBUG_NEIGHBOR_EVENT);

	OSPF6_DEBUG_NEIGHBOR_OFF(OSPF6_DEBUG_NEIGHBOR_STATE
				 | OSPF6_DEBUG_NEIGHBOR_EVENT);
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

void install_element_ospf6_debug_neighbor(void)
{
	install_element(ENABLE_NODE, &debug_ospf6_neighbor_cmd);
	install_element(ENABLE_NODE, &no_debug_ospf6_neighbor_cmd);
	install_element(ENABLE_NODE, &no_debug_ospf6_cmd);
	install_element(CONFIG_NODE, &debug_ospf6_neighbor_cmd);
	install_element(CONFIG_NODE, &no_debug_ospf6_neighbor_cmd);
	install_element(CONFIG_NODE, &no_debug_ospf6_cmd);
}
