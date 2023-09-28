// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 */

#include <zebra.h>

#include "log.h"
#include "prefix.h"
#include "memory.h"
#include "if.h"
#include "vty.h"
#include "plist.h"
#include "lib_errors.h"

#include "pimd.h"
#include "pim_instance.h"
#include "pim_neighbor.h"
#include "pim_time.h"
#include "pim_str.h"
#include "pim_iface.h"
#include "pim_pim.h"
#include "pim_upstream.h"
#include "pim_ifchannel.h"
#include "pim_rp.h"
#include "pim_zebra.h"
#include "pim_join.h"
#include "pim_jp_agg.h"
#include "pim_bfd.h"
#include "pim_register.h"
#include "pim_oil.h"

static void dr_election_by_addr(struct interface *ifp)
{
	struct pim_interface *pim_ifp;
	struct listnode *node;
	struct pim_neighbor *neigh;

	pim_ifp = ifp->info;
	assert(pim_ifp);

	pim_ifp->pim_dr_addr = pim_ifp->primary_address;

	if (PIM_DEBUG_PIM_TRACE) {
		zlog_debug("%s: on interface %s", __func__, ifp->name);
	}

	for (ALL_LIST_ELEMENTS_RO(pim_ifp->pim_neighbor_list, node, neigh)) {
		if (pim_addr_cmp(neigh->source_addr, pim_ifp->pim_dr_addr) > 0)
			pim_ifp->pim_dr_addr = neigh->source_addr;
	}
}

static void dr_election_by_pri(struct interface *ifp)
{
	struct pim_interface *pim_ifp;
	struct listnode *node;
	struct pim_neighbor *neigh;
	uint32_t dr_pri;

	pim_ifp = ifp->info;
	assert(pim_ifp);

	pim_ifp->pim_dr_addr = pim_ifp->primary_address;
	dr_pri = pim_ifp->pim_dr_priority;

	if (PIM_DEBUG_PIM_TRACE) {
		zlog_debug("%s: dr pri %u on interface %s", __func__, dr_pri,
			   ifp->name);
	}

	for (ALL_LIST_ELEMENTS_RO(pim_ifp->pim_neighbor_list, node, neigh)) {
		if (PIM_DEBUG_PIM_TRACE) {
			zlog_info("%s: neigh pri %u addr %pPA if dr addr %pPA",
				  __func__, neigh->dr_priority,
				  &neigh->source_addr, &pim_ifp->pim_dr_addr);
		}
		if ((neigh->dr_priority > dr_pri) ||
		    ((neigh->dr_priority == dr_pri) &&
		     (pim_addr_cmp(neigh->source_addr, pim_ifp->pim_dr_addr) >
		      0))) {
			pim_ifp->pim_dr_addr = neigh->source_addr;
			dr_pri = neigh->dr_priority;
		}
	}
}

/*
  RFC 4601: 4.3.2.  DR Election

  A router's idea of the current DR on an interface can change when a
  PIM Hello message is received, when a neighbor times out, or when a
  router's own DR Priority changes.
 */
int pim_if_dr_election(struct interface *ifp)
{
	struct pim_interface *pim_ifp = ifp->info;
	pim_addr old_dr_addr;

	++pim_ifp->pim_dr_election_count;

	old_dr_addr = pim_ifp->pim_dr_addr;

	if (pim_ifp->pim_dr_num_nondrpri_neighbors) {
		dr_election_by_addr(ifp);
	} else {
		dr_election_by_pri(ifp);
	}

	/* DR changed ? */
	if (pim_addr_cmp(old_dr_addr, pim_ifp->pim_dr_addr)) {

		if (PIM_DEBUG_PIM_EVENTS)
			zlog_debug(
				"%s: DR was %pPA now is %pPA on interface %s",
				__func__, &old_dr_addr, &pim_ifp->pim_dr_addr,
				ifp->name);

		pim_ifp->pim_dr_election_last =
			pim_time_monotonic_sec(); /* timestamp */
		++pim_ifp->pim_dr_election_changes;
		pim_if_update_join_desired(pim_ifp);
		pim_if_update_could_assert(ifp);
		pim_if_update_assert_tracking_desired(ifp);

		if (PIM_I_am_DR(pim_ifp)) {
			pim_ifp->am_i_dr = true;
			pim_clear_nocache_state(pim_ifp);
		} else {
			if (pim_ifp->am_i_dr == true) {
				pim_reg_del_on_couldreg_fail(ifp);
				pim_ifp->am_i_dr = false;
			}
		}

		return 1;
	}

	return 0;
}

static void update_dr_priority(struct pim_neighbor *neigh,
			       pim_hello_options hello_options,
			       uint32_t dr_priority)
{
	pim_hello_options will_set_pri; /* boolean */
	pim_hello_options bit_flip;     /* boolean */
	pim_hello_options pri_change;   /* boolean */

	will_set_pri =
		PIM_OPTION_IS_SET(hello_options, PIM_OPTION_MASK_DR_PRIORITY);

	bit_flip = (will_set_pri
		    != PIM_OPTION_IS_SET(neigh->hello_options,
					 PIM_OPTION_MASK_DR_PRIORITY));

	if (bit_flip) {
		struct pim_interface *pim_ifp = neigh->interface->info;

		/* update num. of neighbors without dr_pri */

		if (will_set_pri) {
			--pim_ifp->pim_dr_num_nondrpri_neighbors;
		} else {
			++pim_ifp->pim_dr_num_nondrpri_neighbors;
		}
	}

	pri_change = (bit_flip || (neigh->dr_priority != dr_priority));

	if (will_set_pri) {
		neigh->dr_priority = dr_priority;
	} else {
		neigh->dr_priority = 0; /* cosmetic unset */
	}

	if (pri_change) {
		/*
		  RFC 4601: 4.3.2.  DR Election

		  A router's idea of the current DR on an interface can change
		  when a
		  PIM Hello message is received, when a neighbor times out, or
		  when a
		  router's own DR Priority changes.
		*/
		pim_if_dr_election(
			neigh->interface); // router's own DR Priority changes
	}
}

static void on_neighbor_timer(struct event *t)
{
	struct pim_neighbor *neigh;
	struct interface *ifp;
	char msg[100];

	neigh = EVENT_ARG(t);

	ifp = neigh->interface;

	if (PIM_DEBUG_PIM_TRACE)
		zlog_debug(
			"Expired %d sec holdtime for neighbor %pPA on interface %s",
			neigh->holdtime, &neigh->source_addr, ifp->name);

	snprintf(msg, sizeof(msg), "%d-sec holdtime expired", neigh->holdtime);
	pim_neighbor_delete(ifp, neigh, msg);

	/*
	  RFC 4601: 4.3.2.  DR Election

	  A router's idea of the current DR on an interface can change when a
	  PIM Hello message is received, when a neighbor times out, or when a
	  router's own DR Priority changes.
	*/
	pim_if_dr_election(ifp); // neighbor times out
}

void pim_neighbor_timer_reset(struct pim_neighbor *neigh, uint16_t holdtime)
{
	neigh->holdtime = holdtime;

	EVENT_OFF(neigh->t_expire_timer);

	/*
	  0xFFFF is request for no holdtime
	 */
	if (neigh->holdtime == 0xFFFF) {
		return;
	}

	if (PIM_DEBUG_PIM_TRACE_DETAIL)
		zlog_debug("%s: starting %u sec timer for neighbor %pPA on %s",
			   __func__, neigh->holdtime, &neigh->source_addr,
			   neigh->interface->name);

	event_add_timer(router->master, on_neighbor_timer, neigh,
			neigh->holdtime, &neigh->t_expire_timer);
}

static void on_neighbor_jp_timer(struct event *t)
{
	struct pim_neighbor *neigh = EVENT_ARG(t);
	struct pim_rpf rpf;

	if (PIM_DEBUG_PIM_TRACE)
		zlog_debug("%s:Sending JP Agg to %pPA on %s with %d groups",
			   __func__, &neigh->source_addr,
			   neigh->interface->name,
			   neigh->upstream_jp_agg->count);

	rpf.source_nexthop.interface = neigh->interface;
	rpf.rpf_addr = neigh->source_addr;
	pim_joinprune_send(&rpf, neigh->upstream_jp_agg);

	event_add_timer(router->master, on_neighbor_jp_timer, neigh,
			router->t_periodic, &neigh->jp_timer);
}

static void pim_neighbor_start_jp_timer(struct pim_neighbor *neigh)
{
	EVENT_OFF(neigh->jp_timer);
	event_add_timer(router->master, on_neighbor_jp_timer, neigh,
			router->t_periodic, &neigh->jp_timer);
}

static struct pim_neighbor *
pim_neighbor_new(struct interface *ifp, pim_addr source_addr,
		 pim_hello_options hello_options, uint16_t holdtime,
		 uint16_t propagation_delay, uint16_t override_interval,
		 uint32_t dr_priority, uint32_t generation_id,
		 struct list *addr_list)
{
	struct pim_interface *pim_ifp;
	struct pim_neighbor *neigh;

	assert(ifp);
	pim_ifp = ifp->info;
	assert(pim_ifp);

	neigh = XCALLOC(MTYPE_PIM_NEIGHBOR, sizeof(*neigh));

	neigh->creation = pim_time_monotonic_sec();
	neigh->source_addr = source_addr;
	neigh->hello_options = hello_options;
	neigh->propagation_delay_msec = propagation_delay;
	neigh->override_interval_msec = override_interval;
	neigh->dr_priority = dr_priority;
	neigh->generation_id = generation_id;
	neigh->prefix_list = addr_list;
	neigh->t_expire_timer = NULL;
	neigh->interface = ifp;

	neigh->upstream_jp_agg = list_new();
	neigh->upstream_jp_agg->cmp = pim_jp_agg_group_list_cmp;
	neigh->upstream_jp_agg->del =
		(void (*)(void *))pim_jp_agg_group_list_free;
	pim_neighbor_start_jp_timer(neigh);

	pim_neighbor_timer_reset(neigh, holdtime);
	/*
	 * The pim_ifstat_hello_sent variable is used to decide if
	 * we should expedite a hello out the interface.  If we
	 * establish a new neighbor, we unfortunately need to
	 * reset the value so that we can know to hurry up and
	 * hello
	 */
	PIM_IF_FLAG_UNSET_HELLO_SENT(pim_ifp->flags);

	if (PIM_DEBUG_PIM_EVENTS)
		zlog_debug("%s: creating PIM neighbor %pPA on interface %s",
			   __func__, &source_addr, ifp->name);

	zlog_notice("PIM NEIGHBOR UP: neighbor %pPA on interface %s",
		    &source_addr, ifp->name);

	if (neigh->propagation_delay_msec
	    > pim_ifp->pim_neighbors_highest_propagation_delay_msec) {
		pim_ifp->pim_neighbors_highest_propagation_delay_msec =
			neigh->propagation_delay_msec;
	}
	if (neigh->override_interval_msec
	    > pim_ifp->pim_neighbors_highest_override_interval_msec) {
		pim_ifp->pim_neighbors_highest_override_interval_msec =
			neigh->override_interval_msec;
	}

	if (!PIM_OPTION_IS_SET(neigh->hello_options,
			       PIM_OPTION_MASK_LAN_PRUNE_DELAY)) {
		/* update num. of neighbors without hello option lan_delay */
		++pim_ifp->pim_number_of_nonlandelay_neighbors;
	}

	if (!PIM_OPTION_IS_SET(neigh->hello_options,
			       PIM_OPTION_MASK_DR_PRIORITY)) {
		/* update num. of neighbors without hello option dr_pri */
		++pim_ifp->pim_dr_num_nondrpri_neighbors;
	}

	// Register PIM Neighbor with BFD
	pim_bfd_info_nbr_create(pim_ifp, neigh);

	return neigh;
}

static void delete_prefix_list(struct pim_neighbor *neigh)
{
	if (neigh->prefix_list) {

#ifdef DUMP_PREFIX_LIST
		struct listnode *p_node;
		struct prefix *p;
		int list_size = neigh->prefix_list
					? (int)listcount(neigh->prefix_list)
					: -1;
		int i = 0;
		for (ALL_LIST_ELEMENTS_RO(neigh->prefix_list, p_node, p)) {
			zlog_debug(
				"%s: DUMP_PREFIX_LIST neigh=%x prefix_list=%x prefix=%x addr=%pFXh [%d/%d]",
				__func__, (unsigned)neigh,
				(unsigned)neigh->prefix_list, (unsigned)p, p, i,
				list_size);
			++i;
		}
#endif

		list_delete(&neigh->prefix_list);
	}
}

void pim_neighbor_free(struct pim_neighbor *neigh)
{
	assert(!neigh->t_expire_timer);

	delete_prefix_list(neigh);

	list_delete(&neigh->upstream_jp_agg);
	EVENT_OFF(neigh->jp_timer);

	bfd_sess_free(&neigh->bfd_session);

	XFREE(MTYPE_PIM_NEIGHBOR, neigh);
}

struct pim_neighbor *pim_neighbor_find_by_secondary(struct interface *ifp,
						    struct prefix *src)
{
	struct pim_interface *pim_ifp;
	struct listnode *node, *pnode;
	struct pim_neighbor *neigh;
	struct prefix *p;

	if (!ifp || !ifp->info)
		return NULL;

	pim_ifp = ifp->info;

	for (ALL_LIST_ELEMENTS_RO(pim_ifp->pim_neighbor_list, node, neigh)) {
		for (ALL_LIST_ELEMENTS_RO(neigh->prefix_list, pnode, p)) {
			if (prefix_same(p, src))
				return neigh;
		}
	}

	return NULL;
}

struct pim_neighbor *pim_neighbor_find(struct interface *ifp,
				       pim_addr source_addr, bool secondary)
{
	struct pim_interface *pim_ifp;
	struct listnode *node;
	struct pim_neighbor *neigh;

	if (!ifp)
		return NULL;

	pim_ifp = ifp->info;
	if (!pim_ifp)
		return NULL;

	for (ALL_LIST_ELEMENTS_RO(pim_ifp->pim_neighbor_list, node, neigh)) {
		if (!pim_addr_cmp(source_addr, neigh->source_addr)) {
			return neigh;
		}
	}

	if (secondary) {
		struct prefix p;

		pim_addr_to_prefix(&p, source_addr);
		return pim_neighbor_find_by_secondary(ifp, &p);
	}

	return NULL;
}

/*
 * Find the *one* interface out
 * this interface.  If more than
 * one return NULL
 */
struct pim_neighbor *pim_neighbor_find_if(struct interface *ifp)
{
	struct pim_interface *pim_ifp = ifp->info;

	if (!pim_ifp || pim_ifp->pim_neighbor_list->count != 1)
		return NULL;

	return listnode_head(pim_ifp->pim_neighbor_list);
}

struct pim_neighbor *
pim_neighbor_add(struct interface *ifp, pim_addr source_addr,
		 pim_hello_options hello_options, uint16_t holdtime,
		 uint16_t propagation_delay, uint16_t override_interval,
		 uint32_t dr_priority, uint32_t generation_id,
		 struct list *addr_list, int send_hello_now)
{
	struct pim_interface *pim_ifp;
	struct pim_neighbor *neigh;

	neigh = pim_neighbor_new(ifp, source_addr, hello_options, holdtime,
				 propagation_delay, override_interval,
				 dr_priority, generation_id, addr_list);
	if (!neigh) {
		return 0;
	}

	pim_ifp = ifp->info;
	assert(pim_ifp);

	listnode_add(pim_ifp->pim_neighbor_list, neigh);

	if (PIM_DEBUG_PIM_TRACE_DETAIL)
		zlog_debug("%s: neighbor %pPA added ", __func__, &source_addr);
	/*
	  RFC 4601: 4.3.2.  DR Election

	  A router's idea of the current DR on an interface can change when a
	  PIM Hello message is received, when a neighbor times out, or when a
	  router's own DR Priority changes.
	*/
	pim_if_dr_election(neigh->interface); // new neighbor -- should not
					      // trigger dr election...

	/*
	  RFC 4601: 4.3.1.  Sending Hello Messages

	  To allow new or rebooting routers to learn of PIM neighbors quickly,
	  when a Hello message is received from a new neighbor, or a Hello
	  message with a new GenID is received from an existing neighbor, a
	  new Hello message should be sent on this interface after a
	  randomized delay between 0 and Triggered_Hello_Delay.

	  This is a bit silly to do it that way.  If I get a new
	  genid we need to send the hello *now* because we've
	  lined up a bunch of join/prune messages to go out the
	  interface.
	*/
	if (send_hello_now)
		pim_hello_restart_now(ifp);
	else
		pim_hello_restart_triggered(neigh->interface);

	pim_upstream_find_new_rpf(pim_ifp->pim);

	/* RNH can send nexthop update prior to PIM neibhor UP
	   in that case nexthop cache would not consider this neighbor
	   as RPF.
	   Upon PIM neighbor UP, iterate all RPs and update
	   nexthop cache with this neighbor.
	 */
	pim_resolve_rp_nh(pim_ifp->pim, neigh);

	pim_rp_setup(pim_ifp->pim);

	sched_rpf_cache_refresh(pim_ifp->pim);
	return neigh;
}

static uint16_t find_neighbors_next_highest_propagation_delay_msec(
	struct interface *ifp, struct pim_neighbor *highest_neigh)
{
	struct pim_interface *pim_ifp;
	struct listnode *neigh_node;
	struct pim_neighbor *neigh;
	uint16_t next_highest_delay_msec;

	pim_ifp = ifp->info;
	assert(pim_ifp);

	next_highest_delay_msec = pim_ifp->pim_propagation_delay_msec;

	for (ALL_LIST_ELEMENTS_RO(pim_ifp->pim_neighbor_list, neigh_node,
				  neigh)) {
		if (neigh == highest_neigh)
			continue;
		if (neigh->propagation_delay_msec > next_highest_delay_msec)
			next_highest_delay_msec = neigh->propagation_delay_msec;
	}

	return next_highest_delay_msec;
}

static uint16_t find_neighbors_next_highest_override_interval_msec(
	struct interface *ifp, struct pim_neighbor *highest_neigh)
{
	struct pim_interface *pim_ifp;
	struct listnode *neigh_node;
	struct pim_neighbor *neigh;
	uint16_t next_highest_interval_msec;

	pim_ifp = ifp->info;
	assert(pim_ifp);

	next_highest_interval_msec = pim_ifp->pim_override_interval_msec;

	for (ALL_LIST_ELEMENTS_RO(pim_ifp->pim_neighbor_list, neigh_node,
				  neigh)) {
		if (neigh == highest_neigh)
			continue;
		if (neigh->override_interval_msec > next_highest_interval_msec)
			next_highest_interval_msec =
				neigh->override_interval_msec;
	}

	return next_highest_interval_msec;
}

void pim_neighbor_delete(struct interface *ifp, struct pim_neighbor *neigh,
			 const char *delete_message)
{
	struct pim_interface *pim_ifp;

	pim_ifp = ifp->info;
	assert(pim_ifp);

	zlog_notice("PIM NEIGHBOR DOWN: neighbor %pPA on interface %s: %s",
		    &neigh->source_addr, ifp->name, delete_message);

	EVENT_OFF(neigh->t_expire_timer);

	pim_if_assert_on_neighbor_down(ifp, neigh->source_addr);

	if (!PIM_OPTION_IS_SET(neigh->hello_options,
			       PIM_OPTION_MASK_LAN_PRUNE_DELAY)) {
		/* update num. of neighbors without hello option lan_delay */

		--pim_ifp->pim_number_of_nonlandelay_neighbors;
	}

	if (!PIM_OPTION_IS_SET(neigh->hello_options,
			       PIM_OPTION_MASK_DR_PRIORITY)) {
		/* update num. of neighbors without dr_pri */

		--pim_ifp->pim_dr_num_nondrpri_neighbors;
	}

	assert(neigh->propagation_delay_msec
	       <= pim_ifp->pim_neighbors_highest_propagation_delay_msec);
	assert(neigh->override_interval_msec
	       <= pim_ifp->pim_neighbors_highest_override_interval_msec);

	if (pim_if_lan_delay_enabled(ifp)) {

		/* will delete a neighbor with highest propagation delay? */
		if (neigh->propagation_delay_msec
		    == pim_ifp->pim_neighbors_highest_propagation_delay_msec) {
			/* then find the next highest propagation delay */
			pim_ifp->pim_neighbors_highest_propagation_delay_msec =
				find_neighbors_next_highest_propagation_delay_msec(
					ifp, neigh);
		}

		/* will delete a neighbor with highest override interval? */
		if (neigh->override_interval_msec
		    == pim_ifp->pim_neighbors_highest_override_interval_msec) {
			/* then find the next highest propagation delay */
			pim_ifp->pim_neighbors_highest_override_interval_msec =
				find_neighbors_next_highest_override_interval_msec(
					ifp, neigh);
		}
	}

	if (PIM_DEBUG_PIM_TRACE) {
		zlog_debug("%s: deleting PIM neighbor %pPA on interface %s",
			   __func__, &neigh->source_addr, ifp->name);
	}

	listnode_delete(pim_ifp->pim_neighbor_list, neigh);

	pim_neighbor_free(neigh);

	sched_rpf_cache_refresh(pim_ifp->pim);
}

void pim_neighbor_delete_all(struct interface *ifp, const char *delete_message)
{
	struct pim_interface *pim_ifp;
	struct listnode *neigh_node;
	struct listnode *neigh_nextnode;
	struct pim_neighbor *neigh;

	pim_ifp = ifp->info;
	assert(pim_ifp);

	for (ALL_LIST_ELEMENTS(pim_ifp->pim_neighbor_list, neigh_node,
			       neigh_nextnode, neigh)) {
		pim_neighbor_delete(ifp, neigh, delete_message);
	}
}

struct prefix *pim_neighbor_find_secondary(struct pim_neighbor *neigh,
					   struct prefix *addr)
{
	struct listnode *node;
	struct prefix *p;

	if (!neigh->prefix_list)
		return 0;

	for (ALL_LIST_ELEMENTS_RO(neigh->prefix_list, node, p)) {
		if (prefix_same(p, addr))
			return p;
	}

	return NULL;
}

/*
  RFC 4601: 4.3.4.  Maintaining Secondary Address Lists

  All the advertised secondary addresses in received Hello messages
  must be checked against those previously advertised by all other
  PIM neighbors on that interface.  If there is a conflict and the
  same secondary address was previously advertised by another
  neighbor, then only the most recently received mapping MUST be
  maintained, and an error message SHOULD be logged to the
  administrator in a rate-limited manner.
*/
static void delete_from_neigh_addr(struct interface *ifp,
				   struct list *addr_list, pim_addr neigh_addr)
{
	struct listnode *addr_node;
	struct prefix *addr;
	struct pim_interface *pim_ifp;

	pim_ifp = ifp->info;
	assert(pim_ifp);

	assert(addr_list);

	/*
	  Scan secondary address list
	*/
	for (ALL_LIST_ELEMENTS_RO(addr_list, addr_node, addr)) {
		struct listnode *neigh_node;
		struct pim_neighbor *neigh;

		if (addr->family != PIM_AF)
			continue;
		/*
		  Scan neighbors
		*/
		for (ALL_LIST_ELEMENTS_RO(pim_ifp->pim_neighbor_list,
					  neigh_node, neigh)) {
			{
				struct prefix *p = pim_neighbor_find_secondary(
					neigh, addr);
				if (p) {
					zlog_info(
						"secondary addr %pFXh recvd from neigh %pPA deleted from neigh %pPA on %s",
						addr, &neigh_addr,
						&neigh->source_addr, ifp->name);

					listnode_delete(neigh->prefix_list, p);
					prefix_free(&p);
				}
			}

		} /* scan neighbors */

	} /* scan addr list */
}

void pim_neighbor_update(struct pim_neighbor *neigh,
			 pim_hello_options hello_options, uint16_t holdtime,
			 uint32_t dr_priority, struct list *addr_list)
{
	struct pim_interface *pim_ifp = neigh->interface->info;
	uint32_t old, new;

	/* Received holdtime ? */
	if (PIM_OPTION_IS_SET(hello_options, PIM_OPTION_MASK_HOLDTIME)) {
		pim_neighbor_timer_reset(neigh, holdtime);
	} else {
		pim_neighbor_timer_reset(neigh,
					 PIM_IF_DEFAULT_HOLDTIME(pim_ifp));
	}

#ifdef DUMP_PREFIX_LIST
	zlog_debug(
		"%s: DUMP_PREFIX_LIST old_prefix_list=%x old_size=%d new_prefix_list=%x new_size=%d",
		__func__, (unsigned)neigh->prefix_list,
		neigh->prefix_list ? (int)listcount(neigh->prefix_list) : -1,
		(unsigned)addr_list,
		addr_list ? (int)listcount(addr_list) : -1);
#endif

	if (neigh->prefix_list == addr_list) {
		if (addr_list) {
			flog_err(
				EC_LIB_DEVELOPMENT,
				"%s: internal error: trying to replace same prefix list=%p",
				__func__, (void *)addr_list);
		}
	} else {
		/* Delete existing secondary address list */
		delete_prefix_list(neigh);
	}

	if (addr_list) {
		delete_from_neigh_addr(neigh->interface, addr_list,
				       neigh->source_addr);
	}

	/* Replace secondary address list */
	neigh->prefix_list = addr_list;

	update_dr_priority(neigh, hello_options, dr_priority);
	new = PIM_OPTION_IS_SET(hello_options, PIM_OPTION_MASK_LAN_PRUNE_DELAY);
	old = PIM_OPTION_IS_SET(neigh->hello_options,
				PIM_OPTION_MASK_LAN_PRUNE_DELAY);

	if (old != new) {
		if (old)
			++pim_ifp->pim_number_of_nonlandelay_neighbors;
		else
			--pim_ifp->pim_number_of_nonlandelay_neighbors;
	}
	/*
	  Copy flags
	 */
	neigh->hello_options = hello_options;
}
