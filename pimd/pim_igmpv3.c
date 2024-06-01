// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 */

#include <zebra.h>
#include "log.h"
#include "memory.h"
#include "if.h"
#include "lib_errors.h"

#include "pimd.h"
#include "pim_instance.h"
#include "pim_iface.h"
#include "pim_igmp.h"
#include "pim_igmpv3.h"
#include "pim_str.h"
#include "pim_util.h"
#include "pim_time.h"
#include "pim_zebra.h"
#include "pim_oil.h"
#include "pim_ssm.h"

static void group_retransmit_timer_on(struct gm_group *group);
static long igmp_group_timer_remain_msec(struct gm_group *group);
static long igmp_source_timer_remain_msec(struct gm_source *source);
static void group_query_send(struct gm_group *group);
static void source_query_send_by_flag(struct gm_group *group,
				      int num_sources_tosend);

static void on_trace(const char *label, struct interface *ifp,
		     struct in_addr from, struct in_addr group_addr,
		     int num_sources, struct in_addr *sources)
{
	if (PIM_DEBUG_GM_TRACE) {
		char from_str[INET_ADDRSTRLEN];
		char group_str[INET_ADDRSTRLEN];

		pim_inet4_dump("<from?>", from, from_str, sizeof(from_str));
		pim_inet4_dump("<group?>", group_addr, group_str,
			       sizeof(group_str));

		zlog_debug("%s: from %s on %s: group=%s sources=%d", label,
			   from_str, ifp->name, group_str, num_sources);
	}
}

static inline long igmp_gmi_msec(struct gm_group *group)
{
	struct pim_interface *pim_ifp = group->interface->info;
	struct gm_sock *igmp;
	struct listnode *sock_node;

	long qrv = 0, qqi = 0;

	for (ALL_LIST_ELEMENTS_RO(pim_ifp->gm_socket_list, sock_node, igmp)) {
		qrv = MAX(qrv, igmp->querier_robustness_variable);
		qqi = MAX(qqi, igmp->querier_query_interval);
	}
	return PIM_IGMP_GMI_MSEC(qrv, qqi,
				 pim_ifp->gm_query_max_response_time_dsec);
}

void igmp_group_reset_gmi(struct gm_group *group)
{
	long group_membership_interval_msec;
	struct interface *ifp;

	ifp = group->interface;

	/*
	  RFC 3376: 8.4. Group Membership Interval

	  The Group Membership Interval is the amount of time that must pass
	  before a multicast router decides there are no more members of a
	  group or a particular source on a network.

	  This value MUST be ((the Robustness Variable) times (the Query
	  Interval)) plus (one Query Response Interval).

	  group_membership_interval_msec = querier_robustness_variable *
					   (1000 * querier_query_interval) +
					   100 * query_response_interval_dsec;
	*/
	group_membership_interval_msec = igmp_gmi_msec(group);

	if (PIM_DEBUG_GM_TRACE) {
		char group_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<group?>", group->group_addr, group_str,
			       sizeof(group_str));
		zlog_debug(
			"Resetting group %s timer to GMI=%ld.%03ld sec on %s",
			group_str, group_membership_interval_msec / 1000,
			group_membership_interval_msec % 1000, ifp->name);
	}

	/*
	  RFC 3376: 6.2.2. Definition of Group Timers

	  The group timer is only used when a group is in EXCLUDE mode and
	  it represents the time for the *filter-mode* of the group to
	  expire and switch to INCLUDE mode.
	*/
	assert(group->group_filtermode_isexcl);

	igmp_group_timer_on(group, group_membership_interval_msec, ifp->name);
}

static void igmp_source_timer(struct event *t)
{
	struct gm_source *source;
	struct gm_group *group;

	source = EVENT_ARG(t);

	group = source->source_group;

	if (PIM_DEBUG_GM_TRACE) {
		char group_str[INET_ADDRSTRLEN];
		char source_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<group?>", group->group_addr, group_str,
			       sizeof(group_str));
		pim_inet4_dump("<source?>", source->source_addr, source_str,
			       sizeof(source_str));
		zlog_debug(
			"%s: Source timer expired for group %s source %s on %s",
			__func__, group_str, source_str,
			group->interface->name);
	}

	/*
	  RFC 3376: 6.3. IGMPv3 Source-Specific Forwarding Rules

	  Group
	  Filter-Mode    Source Timer Value    Action
	  -----------    ------------------    ------
	  INCLUDE        TIMER == 0            Suggest to stop forwarding
					       traffic from source and
					       remove source record.  If
					       there are no more source
					       records for the group, delete
					       group record.

	  EXCLUDE        TIMER == 0            Suggest to not forward
					       traffic from source
					       (DO NOT remove record)

	  Source timer switched from (T > 0) to (T == 0): disable forwarding.
	 */

	if (group->group_filtermode_isexcl) {
		/* EXCLUDE mode */

		igmp_source_forward_stop(source);
	} else {
		/* INCLUDE mode */

		/* igmp_source_delete() will stop forwarding source */
		igmp_source_delete(source);

		/*
		  If there are no more source records for the group, delete
		  group
		  record.
		*/
		if (!listcount(group->group_source_list)) {
			igmp_group_delete_empty_include(group);
		}
	}
}

static void source_timer_off(struct gm_group *group, struct gm_source *source)
{
	if (!source->t_source_timer)
		return;

	if (PIM_DEBUG_GM_TRACE) {
		char group_str[INET_ADDRSTRLEN];
		char source_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<group?>", group->group_addr, group_str,
			       sizeof(group_str));
		pim_inet4_dump("<source?>", source->source_addr, source_str,
			       sizeof(source_str));
		zlog_debug(
			"Cancelling TIMER event for group %s source %s on %s",
			group_str, source_str, group->interface->name);
	}

	EVENT_OFF(source->t_source_timer);
}

static void igmp_source_timer_on(struct gm_group *group,
				 struct gm_source *source, long interval_msec)
{
	source_timer_off(group, source);
	struct pim_interface *pim_ifp = group->interface->info;

	if (PIM_DEBUG_GM_EVENTS) {
		char group_str[INET_ADDRSTRLEN];
		char source_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<group?>", group->group_addr, group_str,
			       sizeof(group_str));
		pim_inet4_dump("<source?>", source->source_addr, source_str,
			       sizeof(source_str));
		zlog_debug(
			"Scheduling %ld.%03ld sec TIMER event for group %s source %s on %s",
			interval_msec / 1000, interval_msec % 1000, group_str,
			source_str, group->interface->name);
	}

	event_add_timer_msec(router->master, igmp_source_timer, source,
			     interval_msec, &source->t_source_timer);

	/*
	  RFC 3376: 6.3. IGMPv3 Source-Specific Forwarding Rules

	  Source timer switched from (T == 0) to (T > 0): enable forwarding.
	*/
	igmp_source_forward_start(pim_ifp->pim, source);
}

void igmp_source_reset_gmi(struct gm_group *group, struct gm_source *source)
{
	long group_membership_interval_msec;
	struct interface *ifp;

	ifp = group->interface;

	group_membership_interval_msec = igmp_gmi_msec(group);

	if (PIM_DEBUG_GM_TRACE) {
		char group_str[INET_ADDRSTRLEN];
		char source_str[INET_ADDRSTRLEN];

		pim_inet4_dump("<group?>", group->group_addr, group_str,
			       sizeof(group_str));
		pim_inet4_dump("<source?>", source->source_addr, source_str,
			       sizeof(source_str));

		zlog_debug(
			"Resetting source %s timer to GMI=%ld.%03ld sec for group %s on %s",
			source_str, group_membership_interval_msec / 1000,
			group_membership_interval_msec % 1000, group_str,
			ifp->name);
	}

	igmp_source_timer_on(group, source, group_membership_interval_msec);
}

static void source_mark_delete_flag(struct gm_group *group)
{
	struct listnode *src_node;
	struct gm_source *src;

	for (ALL_LIST_ELEMENTS_RO(group->group_source_list, src_node, src)) {
		IGMP_SOURCE_DO_DELETE(src->source_flags);
	}
}

static void source_mark_send_flag(struct gm_group *group)
{
	struct listnode *src_node;
	struct gm_source *src;

	for (ALL_LIST_ELEMENTS_RO(group->group_source_list, src_node, src)) {
		IGMP_SOURCE_DO_SEND(src->source_flags);
	}
}

static int source_mark_send_flag_by_timer(struct gm_group *group)
{
	struct listnode *src_node;
	struct gm_source *src;
	int num_marked_sources = 0;

	for (ALL_LIST_ELEMENTS_RO(group->group_source_list, src_node, src)) {
		/* Is source timer running? */
		if (src->t_source_timer) {
			IGMP_SOURCE_DO_SEND(src->source_flags);
			++num_marked_sources;
		} else {
			IGMP_SOURCE_DONT_SEND(src->source_flags);
		}
	}

	return num_marked_sources;
}

static void source_clear_send_flag(struct list *source_list)
{
	struct listnode *src_node;
	struct gm_source *src;

	for (ALL_LIST_ELEMENTS_RO(source_list, src_node, src)) {
		IGMP_SOURCE_DONT_SEND(src->source_flags);
	}
}

/*
  Any source (*,G) is forwarded only if mode is EXCLUDE {empty}
*/
static void group_exclude_fwd_anysrc_ifempty(struct gm_group *group)
{
	struct pim_interface *pim_ifp = group->interface->info;

	assert(group->group_filtermode_isexcl);

	if (listcount(group->group_source_list) < 1) {
		igmp_anysource_forward_start(pim_ifp->pim, group);
	}
}

void igmp_source_free(struct gm_source *source)
{
	/* make sure there is no source timer running */
	assert(!source->t_source_timer);

	XFREE(MTYPE_PIM_IGMP_GROUP_SOURCE, source);
}

/*
  igmp_source_delete:       stop forwarding, and delete the source
  igmp_source_forward_stop: stop forwarding, but keep the source
*/
void igmp_source_delete(struct gm_source *source)
{
	struct gm_group *group;
	struct in_addr src;

	group = source->source_group;

	if (PIM_DEBUG_GM_TRACE) {
		char group_str[INET_ADDRSTRLEN];
		char source_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<group?>", group->group_addr, group_str,
			       sizeof(group_str));
		pim_inet4_dump("<source?>", source->source_addr, source_str,
			       sizeof(source_str));
		zlog_debug(
			"Deleting IGMP source %s for group %s from interface %s c_oil ref_count %d",
			source_str, group_str, group->interface->name,
			source->source_channel_oil
				? source->source_channel_oil->oil_ref_count
				: 0);
	}

	source_timer_off(group, source);
	igmp_source_forward_stop(source);
	source->source_channel_oil = NULL;

	/* sanity check that forwarding has been disabled */
	if (IGMP_SOURCE_TEST_FORWARDING(source->source_flags)) {
		char group_str[INET_ADDRSTRLEN];
		char source_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<group?>", group->group_addr, group_str,
			       sizeof(group_str));
		pim_inet4_dump("<source?>", source->source_addr, source_str,
			       sizeof(source_str));
		zlog_warn(
			"%s: forwarding=ON(!) IGMP source %s for group %s from interface %s",
			__func__, source_str, group_str,
			group->interface->name);
		/* warning only */
	}

	/*
	  notice that listnode_delete() can't be moved
	  into igmp_source_free() because the later is
	  called by list_delete_all_node()
	*/
	listnode_delete(group->group_source_list, source);

	src.s_addr = source->source_addr.s_addr;
	igmp_source_free(source);

	/* Group source list is empty and current source is * then
	 *,G group going away so do not trigger start */
	if (group->group_filtermode_isexcl
	    && (listcount(group->group_source_list) != 0)
	    && src.s_addr != INADDR_ANY) {
		group_exclude_fwd_anysrc_ifempty(group);
	}
}

static void source_delete_by_flag(struct list *source_list)
{
	struct listnode *src_node;
	struct listnode *src_nextnode;
	struct gm_source *src;

	for (ALL_LIST_ELEMENTS(source_list, src_node, src_nextnode, src))
		if (IGMP_SOURCE_TEST_DELETE(src->source_flags))
			igmp_source_delete(src);
}

void igmp_source_delete_expired(struct list *source_list)
{
	struct listnode *src_node;
	struct listnode *src_nextnode;
	struct gm_source *src;

	for (ALL_LIST_ELEMENTS(source_list, src_node, src_nextnode, src))
		if (!src->t_source_timer)
			igmp_source_delete(src);
}

struct gm_source *igmp_find_source_by_addr(struct gm_group *group,
					   struct in_addr src_addr)
{
	struct listnode *src_node;
	struct gm_source *src;

	for (ALL_LIST_ELEMENTS_RO(group->group_source_list, src_node, src))
		if (src_addr.s_addr == src->source_addr.s_addr)
			return src;

	return 0;
}

struct gm_source *igmp_get_source_by_addr(struct gm_group *group,
					  struct in_addr src_addr, bool *new)
{
	struct gm_source *src;

	if (new)
		*new = false;

	src = igmp_find_source_by_addr(group, src_addr);
	if (src)
		return src;

	if (PIM_DEBUG_GM_TRACE) {
		char group_str[INET_ADDRSTRLEN];
		char source_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<group?>", group->group_addr, group_str,
			       sizeof(group_str));
		pim_inet4_dump("<source?>", src_addr, source_str,
			       sizeof(source_str));
		zlog_debug(
			"Creating new IGMP source %s for group %s on interface %s",
			source_str, group_str, group->interface->name);
	}

	src = XCALLOC(MTYPE_PIM_IGMP_GROUP_SOURCE, sizeof(*src));

	if (new)
		*new = true;

	src->t_source_timer = NULL;
	src->source_group = group; /* back pointer */
	src->source_addr = src_addr;
	src->source_creation = pim_time_monotonic_sec();
	src->source_flags = 0;
	src->source_query_retransmit_count = 0;
	src->source_channel_oil = NULL;

	listnode_add(group->group_source_list, src);

	return src;
}

static void allow(struct gm_sock *igmp, struct in_addr from,
		  struct in_addr group_addr, int num_sources,
		  struct in_addr *sources)
{
	struct gm_source *source;
	struct gm_group *group;
	int i;

	if (num_sources == 0) {
		/*
		  RFC 3376: 3.1. Socket-State
		  If the requested filter mode is INCLUDE *and* the requested
		  source list is empty, then the entry corresponding to the
		  requested interface and multicast address is deleted if
		  present. If no such entry is present, the request is ignored.
		  So, deleting the group present.
		*/
		group = find_group_by_addr(igmp, group_addr);
		if (!group) {
			return;
		}
		if (group->group_filtermode_isexcl) {
			if (listcount(group->group_source_list) == 1) {
				struct in_addr star = {.s_addr = INADDR_ANY};

				source = igmp_find_source_by_addr(group, star);
				if (source)
					igmp_source_reset_gmi(group, source);
			}
		} else {
			igmp_group_delete(group);
		}

		return;
	}

	/* non-existent group is created as INCLUDE {empty} */
	group = igmp_add_group_by_addr(igmp, group_addr);
	if (!group) {
		return;
	}

	/* scan received sources */
	for (i = 0; i < num_sources; ++i) {
		struct in_addr *src_addr;

		src_addr = sources + i;

		source = igmp_get_source_by_addr(group, *src_addr, NULL);
		if (!source)
			continue;

		/*
		  RFC 3376: 6.4.1. Reception of Current-State Records

		  When receiving IS_IN reports for groups in EXCLUDE mode is
		  sources should be moved from set with (timers = 0) to set with
		  (timers > 0).

		  igmp_source_reset_gmi() below, resetting the source timers to
		  GMI, accomplishes this.
		*/
		igmp_source_reset_gmi(group, source);

	} /* scan received sources */
}

void igmpv3_report_isin(struct gm_sock *igmp, struct in_addr from,
			struct in_addr group_addr, int num_sources,
			struct in_addr *sources)
{
	on_trace(__func__, igmp->interface, from, group_addr, num_sources,
		 sources);

	allow(igmp, from, group_addr, num_sources, sources);
}

static void isex_excl(struct gm_group *group, int num_sources,
		      struct in_addr *sources)
{
	struct gm_source *source;
	int i;

	/* EXCLUDE mode */
	assert(group->group_filtermode_isexcl);

	/* E.1: set deletion flag for known sources (X,Y) */
	source_mark_delete_flag(group);

	/* scan received sources (A) */
	for (i = 0; i < num_sources; ++i) {
		struct in_addr *src_addr;
		bool new;

		src_addr = sources + i;

		/* E.2: lookup reported source from (A) in (X,Y) */
		source = igmp_get_source_by_addr(group, *src_addr, &new);
		if (!source)
			continue;

		if (!new) {
			/* E.3: if found, clear deletion flag: (X*A) or (Y*A) */
			IGMP_SOURCE_DONT_DELETE(source->source_flags);
		} else {
			/* E.4: if not found, create source with timer=GMI:
			 * (A-X-Y) */
			assert(!source->t_source_timer); /* timer == 0 */
			igmp_source_reset_gmi(group, source);
			assert(source->t_source_timer); /* (A-X-Y) timer > 0 */
		}

	} /* scan received sources */

	/*
	 * If we are in isexcl mode and num_sources == 0
	 * than that means we have a *,g entry that
	 * needs to be handled
	 */
	if (group->group_filtermode_isexcl && num_sources == 0) {
		struct in_addr star = {.s_addr = INADDR_ANY};
		source = igmp_find_source_by_addr(group, star);
		if (source) {
			IGMP_SOURCE_DONT_DELETE(source->source_flags);
			igmp_source_reset_gmi(group, source);
		}
	}

	/* E.5: delete all sources marked with deletion flag: (X-A) and (Y-A) */
	source_delete_by_flag(group->group_source_list);
}

static void isex_incl(struct gm_group *group, int num_sources,
		      struct in_addr *sources)
{
	int i;

	/* INCLUDE mode */
	assert(!group->group_filtermode_isexcl);

	/* I.1: set deletion flag for known sources (A) */
	source_mark_delete_flag(group);

	/* scan received sources (B) */
	for (i = 0; i < num_sources; ++i) {
		struct gm_source *source;
		struct in_addr *src_addr;
		bool new;

		src_addr = sources + i;

		/* I.2: lookup reported source (B) */
		source = igmp_get_source_by_addr(group, *src_addr, &new);
		if (!source)
			continue;

		if (!new) {
			/* I.3: if found, clear deletion flag (A*B) */
			IGMP_SOURCE_DONT_DELETE(source->source_flags);
		} else {
			/* I.4: if not found, create source with timer=0 (B-A)
			 */
			assert(!source->t_source_timer); /* (B-A) timer=0 */
		}

	} /* scan received sources */

	/* I.5: delete all sources marked with deletion flag (A-B) */
	source_delete_by_flag(group->group_source_list);

	group->group_filtermode_isexcl = 1; /* boolean=true */

	assert(group->group_filtermode_isexcl);

	group_exclude_fwd_anysrc_ifempty(group);
}

void igmpv3_report_isex(struct gm_sock *igmp, struct in_addr from,
			struct in_addr group_addr, int num_sources,
			struct in_addr *sources, int from_igmp_v2_report)
{
	struct interface *ifp = igmp->interface;
	struct gm_group *group;

	on_trace(__func__, ifp, from, group_addr, num_sources, sources);

	if (pim_is_group_filtered(ifp->info, &group_addr))
		return;

	/* non-existent group is created as INCLUDE {empty} */
	group = igmp_add_group_by_addr(igmp, group_addr);
	if (!group) {
		return;
	}

	/* So we can display how we learned the group in our show command output
	 */
	if (from_igmp_v2_report)
		group->igmp_version = 2;

	if (group->group_filtermode_isexcl) {
		/* EXCLUDE mode */
		isex_excl(group, num_sources, sources);
	} else {
		/* INCLUDE mode */
		isex_incl(group, num_sources, sources);
		assert(group->group_filtermode_isexcl);
	}

	assert(group->group_filtermode_isexcl);

	igmp_group_reset_gmi(group);
}

static void toin_incl(struct gm_group *group, int num_sources,
		      struct in_addr *sources)
{
	int num_sources_tosend = listcount(group->group_source_list);
	int i;

	/* Set SEND flag for all known sources (A) */
	source_mark_send_flag(group);

	/* Scan received sources (B) */
	for (i = 0; i < num_sources; ++i) {
		struct gm_source *source;
		struct in_addr *src_addr;
		bool new;

		src_addr = sources + i;

		/* Lookup reported source (B) */
		source = igmp_get_source_by_addr(group, *src_addr, &new);
		if (!source)
			continue;

		if (!new) {
			/* If found, clear SEND flag (A*B) */
			IGMP_SOURCE_DONT_SEND(source->source_flags);
			--num_sources_tosend;
		}

		/* (B)=GMI */
		igmp_source_reset_gmi(group, source);
	}

	/* Send sources marked with SEND flag: Q(G,A-B) */
	if (num_sources_tosend > 0) {
		source_query_send_by_flag(group, num_sources_tosend);
	}
}

static void toin_excl(struct gm_group *group, int num_sources,
		      struct in_addr *sources)
{
	int num_sources_tosend;
	int i;

	/* Set SEND flag for X (sources with timer > 0) */
	num_sources_tosend = source_mark_send_flag_by_timer(group);

	/* Scan received sources (A) */
	for (i = 0; i < num_sources; ++i) {
		struct gm_source *source;
		struct in_addr *src_addr;
		bool new;

		src_addr = sources + i;

		/* Lookup reported source (A) */
		source = igmp_get_source_by_addr(group, *src_addr, &new);
		if (!source)
			continue;

		if (source->t_source_timer) {
			/* If found and timer running, clear SEND flag
			 * (X*A) */
			IGMP_SOURCE_DONT_SEND(source->source_flags);
			--num_sources_tosend;
		}

		/* (A)=GMI */
		igmp_source_reset_gmi(group, source);
	}

	/* Send sources marked with SEND flag: Q(G,X-A) */
	if (num_sources_tosend > 0) {
		source_query_send_by_flag(group, num_sources_tosend);
	}

	/* Send Q(G) */
	group_query_send(group);
}

void igmpv3_report_toin(struct gm_sock *igmp, struct in_addr from,
			struct in_addr group_addr, int num_sources,
			struct in_addr *sources)
{
	struct interface *ifp = igmp->interface;
	struct gm_group *group;

	on_trace(__func__, ifp, from, group_addr, num_sources, sources);

	/*
	 * If the requested filter mode is INCLUDE *and* the requested source
	 * list is empty, then the entry corresponding to the requested
	 * interface and multicast address is deleted if present.  If no such
	 * entry is present, the request is ignored.
	 */
	if (num_sources) {
		/* non-existent group is created as INCLUDE {empty} */
		group = igmp_add_group_by_addr(igmp, group_addr);
		if (!group) {
			return;
		}
	} else {
		group = find_group_by_addr(igmp, group_addr);
		if (!group)
			return;
	}

	if (group->group_filtermode_isexcl) {
		/* EXCLUDE mode */
		toin_excl(group, num_sources, sources);
	} else {
		/* INCLUDE mode */
		toin_incl(group, num_sources, sources);
	}
}

static void toex_incl(struct gm_group *group, int num_sources,
		      struct in_addr *sources)
{
	int num_sources_tosend = 0;
	int i;

	assert(!group->group_filtermode_isexcl);

	/* Set DELETE flag for all known sources (A) */
	source_mark_delete_flag(group);

	/* Clear off SEND flag from all known sources (A) */
	source_clear_send_flag(group->group_source_list);

	/* Scan received sources (B) */
	for (i = 0; i < num_sources; ++i) {
		struct gm_source *source;
		struct in_addr *src_addr;
		bool new;

		src_addr = sources + i;

		/* Lookup reported source (B) */
		source = igmp_get_source_by_addr(group, *src_addr, &new);
		if (!new) {
			/* If found, clear deletion flag: (A*B) */
			IGMP_SOURCE_DONT_DELETE(source->source_flags);
			/* and set SEND flag (A*B) */
			IGMP_SOURCE_DO_SEND(source->source_flags);
			++num_sources_tosend;
		}

	} /* Scan received sources (B) */

	group->group_filtermode_isexcl = 1; /* boolean=true */

	/* Delete all sources marked with DELETE flag (A-B) */
	source_delete_by_flag(group->group_source_list);

	/* Send sources marked with SEND flag: Q(G,A*B) */
	if (num_sources_tosend > 0) {
		source_query_send_by_flag(group, num_sources_tosend);
	}

	assert(group->group_filtermode_isexcl);

	group_exclude_fwd_anysrc_ifempty(group);
}

static void toex_excl(struct gm_group *group, int num_sources,
		      struct in_addr *sources)
{
	int num_sources_tosend = 0;
	int i;

	/* set DELETE flag for all known sources (X,Y) */
	source_mark_delete_flag(group);

	/* clear off SEND flag from all known sources (X,Y) */
	source_clear_send_flag(group->group_source_list);

	if (num_sources == 0) {
		struct gm_source *source;
		struct in_addr any = {.s_addr = INADDR_ANY};

		source = igmp_find_source_by_addr(group, any);
		if (source)
			IGMP_SOURCE_DONT_DELETE(source->source_flags);
	}

	/* scan received sources (A) */
	for (i = 0; i < num_sources; ++i) {
		struct gm_source *source;
		struct in_addr *src_addr;
		bool new;

		src_addr = sources + i;

		/* lookup reported source (A) in known sources (X,Y) */
		source = igmp_get_source_by_addr(group, *src_addr, &new);
		if (!source)
			continue;

		if (!new) {
			/* if found, clear off DELETE flag from reported source
			 * (A) */
			IGMP_SOURCE_DONT_DELETE(source->source_flags);
		} else {
			/* if not found, create source with Group Timer:
			 * (A-X-Y)=Group Timer */
			long group_timer_msec;

			assert(!source->t_source_timer); /* timer == 0 */
			group_timer_msec = igmp_group_timer_remain_msec(group);
			igmp_source_timer_on(group, source, group_timer_msec);
			assert(source->t_source_timer); /* (A-X-Y) timer > 0 */

			/* make sure source is created with DELETE flag unset */
			assert(!IGMP_SOURCE_TEST_DELETE(source->source_flags));
		}

		/* make sure reported source has DELETE flag unset */
		assert(!IGMP_SOURCE_TEST_DELETE(source->source_flags));

		if (source->t_source_timer) {
			/* if source timer>0 mark SEND flag: Q(G,A-Y) */
			IGMP_SOURCE_DO_SEND(source->source_flags);
			++num_sources_tosend;
		}

	} /* scan received sources (A) */

	/*
	  delete all sources marked with DELETE flag:
	  Delete (X-A)
	  Delete (Y-A)
	*/
	source_delete_by_flag(group->group_source_list);

	/* send sources marked with SEND flag: Q(G,A-Y) */
	if (num_sources_tosend > 0) {
		source_query_send_by_flag(group, num_sources_tosend);
	}
}

void igmpv3_report_toex(struct gm_sock *igmp, struct in_addr from,
			struct in_addr group_addr, int num_sources,
			struct in_addr *sources)
{
	struct interface *ifp = igmp->interface;
	struct gm_group *group;

	on_trace(__func__, ifp, from, group_addr, num_sources, sources);

	/* non-existent group is created as INCLUDE {empty} */
	group = igmp_add_group_by_addr(igmp, group_addr);
	if (!group) {
		return;
	}

	if (group->group_filtermode_isexcl) {
		/* EXCLUDE mode */
		toex_excl(group, num_sources, sources);
	} else {
		/* INCLUDE mode */
		toex_incl(group, num_sources, sources);
		assert(group->group_filtermode_isexcl);
	}
	assert(group->group_filtermode_isexcl);

	/* Group Timer=GMI */
	igmp_group_reset_gmi(group);
}

void igmpv3_report_allow(struct gm_sock *igmp, struct in_addr from,
			 struct in_addr group_addr, int num_sources,
			 struct in_addr *sources)
{
	on_trace(__func__, igmp->interface, from, group_addr, num_sources,
		 sources);

	allow(igmp, from, group_addr, num_sources, sources);
}

static void igmp_send_query_group(struct gm_group *group, char *query_buf,
				  size_t query_buf_size, int num_sources,
				  int s_flag)
{
	struct interface *ifp = group->interface;
	struct pim_interface *pim_ifp = ifp->info;
	struct gm_sock *igmp;
	struct listnode *sock_node;

	for (ALL_LIST_ELEMENTS_RO(pim_ifp->gm_socket_list, sock_node, igmp)) {
		igmp_send_query(
			pim_ifp->igmp_version, group, query_buf, query_buf_size,
			num_sources, group->group_addr, group->group_addr,
			pim_ifp->gm_specific_query_max_response_time_dsec,
			s_flag, igmp);
	}
}

/*
  RFC3376: 6.6.3.1. Building and Sending Group Specific Queries

  When transmitting a group specific query, if the group timer is
  larger than LMQT, the "Suppress Router-Side Processing" bit is set
  in the query message.
*/
static void group_retransmit_group(struct gm_group *group)
{
	struct pim_interface *pim_ifp;
	long lmqc;      /* Last Member Query Count */
	long lmqi_msec; /* Last Member Query Interval */
	long lmqt_msec; /* Last Member Query Time */
	int s_flag;
	int query_buf_size;

	pim_ifp = group->interface->info;

	if (pim_ifp->igmp_version == 3) {
		query_buf_size = PIM_IGMP_BUFSIZE_WRITE;
	} else {
		query_buf_size = IGMP_V12_MSG_SIZE;
	}

	char query_buf[query_buf_size];

	lmqc = pim_ifp->gm_last_member_query_count;
	lmqi_msec = 100 * pim_ifp->gm_specific_query_max_response_time_dsec;
	lmqt_msec = lmqc * lmqi_msec;

	/*
	  RFC3376: 6.6.3.1. Building and Sending Group Specific Queries

	  When transmitting a group specific query, if the group timer is
	  larger than LMQT, the "Suppress Router-Side Processing" bit is set
	  in the query message.
	*/
	s_flag = igmp_group_timer_remain_msec(group) > lmqt_msec;

	if (PIM_DEBUG_GM_TRACE) {
		char group_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<group?>", group->group_addr, group_str,
			       sizeof(group_str));
		zlog_debug(
			"retransmit_group_specific_query: group %s on %s: s_flag=%d count=%d",
			group_str, group->interface->name, s_flag,
			group->group_specific_query_retransmit_count);
	}

	/*
	  RFC3376: 4.1.12. IP Destination Addresses for Queries

	  Group-Specific and Group-and-Source-Specific Queries are sent with
	  an IP destination address equal to the multicast address of
	  interest.
	*/

	igmp_send_query_group(group, query_buf, sizeof(query_buf), 0, s_flag);
}

/*
  RFC3376: 6.6.3.2. Building and Sending Group and Source Specific Queries

  When building a group and source specific query for a group G, two
  separate query messages are sent for the group.  The first one has
  the "Suppress Router-Side Processing" bit set and contains all the
  sources with retransmission state and timers greater than LMQT.  The
  second has the "Suppress Router-Side Processing" bit clear and
  contains all the sources with retransmission state and timers lower
  or equal to LMQT.  If either of the two calculated messages does not
  contain any sources, then its transmission is suppressed.
 */
static int group_retransmit_sources(struct gm_group *group,
				    int send_with_sflag_set)
{
	struct pim_interface *pim_ifp;
	long lmqc;      /* Last Member Query Count */
	long lmqi_msec; /* Last Member Query Interval */
	long lmqt_msec; /* Last Member Query Time */
	char query_buf1[PIM_IGMP_BUFSIZE_WRITE]; /* 1 = with s_flag set */
	char query_buf2[PIM_IGMP_BUFSIZE_WRITE]; /* 2 = with s_flag clear */
	int query_buf1_max_sources;
	int query_buf2_max_sources;
	struct in_addr *source_addr1;
	struct in_addr *source_addr2;
	int num_sources_tosend1;
	int num_sources_tosend2;
	struct listnode *src_node;
	struct gm_source *src;
	int num_retransmit_sources_left = 0;

	source_addr1 = (struct in_addr *)(query_buf1 + IGMP_V3_SOURCES_OFFSET);
	source_addr2 = (struct in_addr *)(query_buf2 + IGMP_V3_SOURCES_OFFSET);

	pim_ifp = group->interface->info;

	lmqc = pim_ifp->gm_last_member_query_count;
	lmqi_msec = 100 * pim_ifp->gm_specific_query_max_response_time_dsec;
	lmqt_msec = lmqc * lmqi_msec;

	/* Scan all group sources */
	for (ALL_LIST_ELEMENTS_RO(group->group_source_list, src_node, src)) {

		/* Source has retransmission state? */
		if (src->source_query_retransmit_count < 1)
			continue;

		if (--src->source_query_retransmit_count > 0) {
			++num_retransmit_sources_left;
		}

		/* Copy source address into appropriate query buffer */
		if (igmp_source_timer_remain_msec(src) > lmqt_msec) {
			*source_addr1 = src->source_addr;
			++source_addr1;
		} else {
			*source_addr2 = src->source_addr;
			++source_addr2;
		}
	}

	num_sources_tosend1 =
		source_addr1
		- (struct in_addr *)(query_buf1 + IGMP_V3_SOURCES_OFFSET);
	num_sources_tosend2 =
		source_addr2
		- (struct in_addr *)(query_buf2 + IGMP_V3_SOURCES_OFFSET);

	if (PIM_DEBUG_GM_TRACE) {
		char group_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<group?>", group->group_addr, group_str,
			       sizeof(group_str));
		zlog_debug(
			"retransmit_grp&src_specific_query: group %s on %s: srcs_with_sflag=%d srcs_wo_sflag=%d will_send_sflag=%d retransmit_src_left=%d",
			group_str, group->interface->name, num_sources_tosend1,
			num_sources_tosend2, send_with_sflag_set,
			num_retransmit_sources_left);
	}

	if (num_sources_tosend1 > 0) {
		/*
		  Send group-and-source-specific query with s_flag set and all
		  sources with timers greater than LMQT.
		*/

		if (send_with_sflag_set) {

			query_buf1_max_sources =
				(sizeof(query_buf1) - IGMP_V3_SOURCES_OFFSET)
				>> 2;
			if (num_sources_tosend1 > query_buf1_max_sources) {
				char group_str[INET_ADDRSTRLEN];
				pim_inet4_dump("<group?>", group->group_addr,
					       group_str, sizeof(group_str));
				zlog_warn(
					"%s: group %s on %s: s_flag=1 unable to fit %d sources into buf_size=%zu (max_sources=%d)",
					__func__, group_str,
					group->interface->name,
					num_sources_tosend1, sizeof(query_buf1),
					query_buf1_max_sources);
			} else {
				/*
				  RFC3376: 4.1.12. IP Destination Addresses for
				  Queries

				  Group-Specific and Group-and-Source-Specific
				  Queries are sent with
				  an IP destination address equal to the
				  multicast address of
				  interest.
				*/

				igmp_send_query_group(
					group, query_buf1, sizeof(query_buf1),
					num_sources_tosend1, 1 /* s_flag */);
			}

		} /* send_with_sflag_set */
	}

	if (num_sources_tosend2 > 0) {
		/*
		  Send group-and-source-specific query with s_flag clear and all
		  sources with timers lower or equal to LMQT.
		*/

		query_buf2_max_sources =
			(sizeof(query_buf2) - IGMP_V3_SOURCES_OFFSET) >> 2;
		if (num_sources_tosend2 > query_buf2_max_sources) {
			char group_str[INET_ADDRSTRLEN];
			pim_inet4_dump("<group?>", group->group_addr, group_str,
				       sizeof(group_str));
			zlog_warn(
				"%s: group %s on %s: s_flag=0 unable to fit %d sources into buf_size=%zu (max_sources=%d)",
				__func__, group_str, group->interface->name,
				num_sources_tosend2, sizeof(query_buf2),
				query_buf2_max_sources);
		} else {
			/*
			  RFC3376: 4.1.12. IP Destination Addresses for Queries

			  Group-Specific and Group-and-Source-Specific Queries
			  are sent with
			  an IP destination address equal to the multicast
			  address of
			  interest.
			*/

			igmp_send_query_group(
				group, query_buf2, sizeof(query_buf2),
				num_sources_tosend2, 0 /* s_flag */);
		}
	}

	return num_retransmit_sources_left;
}

static void igmp_group_retransmit(struct event *t)
{
	struct gm_group *group;
	int num_retransmit_sources_left;
	int send_with_sflag_set; /* boolean */

	group = EVENT_ARG(t);

	if (PIM_DEBUG_GM_TRACE) {
		char group_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<group?>", group->group_addr, group_str,
			       sizeof(group_str));
		zlog_debug("group_retransmit_timer: group %s on %s", group_str,
			   group->interface->name);
	}

	/* Retransmit group-specific queries? (RFC3376: 6.6.3.1) */
	if (group->group_specific_query_retransmit_count > 0) {

		/* Retransmit group-specific queries (RFC3376: 6.6.3.1) */
		group_retransmit_group(group);
		--group->group_specific_query_retransmit_count;

		/*
		  RFC3376: 6.6.3.2
		  If a group specific query is scheduled to be transmitted at
		  the
		  same time as a group and source specific query for the same
		  group,
		  then transmission of the group and source specific message
		  with the
		  "Suppress Router-Side Processing" bit set may be suppressed.
		*/
		send_with_sflag_set = 0; /* boolean=false */
	} else {
		send_with_sflag_set = 1; /* boolean=true */
	}

	/* Retransmit group-and-source-specific queries (RFC3376: 6.6.3.2) */
	num_retransmit_sources_left =
		group_retransmit_sources(group, send_with_sflag_set);

	/*
	  Keep group retransmit timer running if there is any retransmit
	  counter pending
	*/
	if ((num_retransmit_sources_left > 0)
	    || (group->group_specific_query_retransmit_count > 0)) {
		group_retransmit_timer_on(group);
	}
}

/*
  group_retransmit_timer_on:
  if group retransmit timer isn't running, starts it;
  otherwise, do nothing
*/
static void group_retransmit_timer_on(struct gm_group *group)
{
	struct pim_interface *pim_ifp;
	long lmqi_msec; /* Last Member Query Interval */

	/* if group retransmit timer is running, do nothing */
	if (group->t_group_query_retransmit_timer) {
		return;
	}

	pim_ifp = group->interface->info;

	lmqi_msec = 100 * pim_ifp->gm_specific_query_max_response_time_dsec;

	if (PIM_DEBUG_GM_TRACE) {
		char group_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<group?>", group->group_addr, group_str,
			       sizeof(group_str));
		zlog_debug(
			"Scheduling %ld.%03ld sec retransmit timer for group %s on %s",
			lmqi_msec / 1000, lmqi_msec % 1000, group_str,
			group->interface->name);
	}

	event_add_timer_msec(router->master, igmp_group_retransmit, group,
			     lmqi_msec, &group->t_group_query_retransmit_timer);
}

static long igmp_group_timer_remain_msec(struct gm_group *group)
{
	return pim_time_timer_remain_msec(group->t_group_timer);
}

static long igmp_source_timer_remain_msec(struct gm_source *source)
{
	return pim_time_timer_remain_msec(source->t_source_timer);
}

/*
  RFC3376: 6.6.3.1. Building and Sending Group Specific Queries
*/
static void group_query_send(struct gm_group *group)
{
	struct pim_interface *pim_ifp;
	long lmqc; /* Last Member Query Count */

	pim_ifp = group->interface->info;
	lmqc = pim_ifp->gm_last_member_query_count;

	/* lower group timer to lmqt */
	igmp_group_timer_lower_to_lmqt(group);

	/* reset retransmission counter */
	group->group_specific_query_retransmit_count = lmqc;

	/* immediately send group specific query (decrease retransmit counter by
	 * 1)*/
	group_retransmit_group(group);

	/* make sure group retransmit timer is running */
	group_retransmit_timer_on(group);
}

/*
  RFC3376: 6.6.3.2. Building and Sending Group and Source Specific Queries
*/
static void source_query_send_by_flag(struct gm_group *group,
				      int num_sources_tosend)
{
	struct pim_interface *pim_ifp;
	struct listnode *src_node;
	struct gm_source *src;
	long lmqc;      /* Last Member Query Count */
	long lmqi_msec; /* Last Member Query Interval */
	long lmqt_msec; /* Last Member Query Time */

	assert(num_sources_tosend > 0);

	pim_ifp = group->interface->info;

	lmqc = pim_ifp->gm_last_member_query_count;
	lmqi_msec = 100 * pim_ifp->gm_specific_query_max_response_time_dsec;
	lmqt_msec = lmqc * lmqi_msec;

	/*
	  RFC3376: 6.6.3.2. Building and Sending Group and Source Specific
	  Queries

	  (...) for each of the sources in X of group G, with source timer
	  larger
	  than LMQT:
	  o Set number of retransmissions for each source to [Last Member
	  Query Count].
	  o Lower source timer to LMQT.
	*/
	for (ALL_LIST_ELEMENTS_RO(group->group_source_list, src_node, src)) {
		if (IGMP_SOURCE_TEST_SEND(src->source_flags)) {
			/* source "src" in X of group G */
			if (igmp_source_timer_remain_msec(src) > lmqt_msec) {
				src->source_query_retransmit_count = lmqc;
				igmp_source_timer_lower_to_lmqt(src);
			}
		}
	}

	/* send group-and-source specific queries */
	group_retransmit_sources(group, 1 /* send_with_sflag_set=true */);

	/* make sure group retransmit timer is running */
	group_retransmit_timer_on(group);
}

static void block_excl(struct gm_group *group, int num_sources,
		       struct in_addr *sources)
{
	int num_sources_tosend = 0;
	int i;

	/* 1. clear off SEND flag from all known sources (X,Y) */
	source_clear_send_flag(group->group_source_list);

	/* 2. scan received sources (A) */
	for (i = 0; i < num_sources; ++i) {
		struct gm_source *source;
		struct in_addr *src_addr;
		bool new;

		src_addr = sources + i;

		/* lookup reported source (A) in known sources (X,Y) */
		source = igmp_get_source_by_addr(group, *src_addr, &new);
		if (!source)
			continue;

		if (new) {
			/* 3: if not found, create source with Group Timer:
			 * (A-X-Y)=Group Timer */
			long group_timer_msec;

			assert(!source->t_source_timer); /* timer == 0 */
			group_timer_msec = igmp_group_timer_remain_msec(group);
			igmp_source_timer_on(group, source, group_timer_msec);
			assert(source->t_source_timer); /* (A-X-Y) timer > 0 */
		}

		if (source->t_source_timer) {
			/* 4. if source timer>0 mark SEND flag: Q(G,A-Y) */
			IGMP_SOURCE_DO_SEND(source->source_flags);
			++num_sources_tosend;
		}
	}

	/* 5. send sources marked with SEND flag: Q(G,A-Y) */
	if (num_sources_tosend > 0) {
		source_query_send_by_flag(group, num_sources_tosend);
	}
}

static void block_incl(struct gm_group *group, int num_sources,
		       struct in_addr *sources)
{
	int num_sources_tosend = 0;
	int i;

	/* 1. clear off SEND flag from all known sources (B) */
	source_clear_send_flag(group->group_source_list);

	/* 2. scan received sources (A) */
	for (i = 0; i < num_sources; ++i) {
		struct gm_source *source;
		struct in_addr *src_addr;

		src_addr = sources + i;

		/* lookup reported source (A) in known sources (B) */
		source = igmp_find_source_by_addr(group, *src_addr);
		if (source) {
			/* 3. if found (A*B), mark SEND flag: Q(G,A*B) */
			IGMP_SOURCE_DO_SEND(source->source_flags);
			++num_sources_tosend;
		}
	}

	/* 4. send sources marked with SEND flag: Q(G,A*B) */
	if (num_sources_tosend > 0) {
		source_query_send_by_flag(group, num_sources_tosend);
	}
}

void igmpv3_report_block(struct gm_sock *igmp, struct in_addr from,
			 struct in_addr group_addr, int num_sources,
			 struct in_addr *sources)
{
	struct interface *ifp = igmp->interface;
	struct gm_group *group;

	on_trace(__func__, ifp, from, group_addr, num_sources, sources);

	/* non-existent group is created as INCLUDE {empty} */
	group = igmp_add_group_by_addr(igmp, group_addr);
	if (!group) {
		return;
	}

	if (group->group_filtermode_isexcl) {
		/* EXCLUDE mode */
		block_excl(group, num_sources, sources);
	} else {
		/* INCLUDE mode */
		block_incl(group, num_sources, sources);
	}
}

void igmp_group_timer_lower_to_lmqt(struct gm_group *group)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;
	char *ifname;
	int lmqi_dsec; /* Last Member Query Interval */
	int lmqc;      /* Last Member Query Count */
	int lmqt_msec; /* Last Member Query Time */

	/*
	  RFC 3376: 6.2.2. Definition of Group Timers

	  The group timer is only used when a group is in EXCLUDE mode and
	  it represents the time for the *filter-mode* of the group to
	  expire and switch to INCLUDE mode.
	*/
	if (!group->group_filtermode_isexcl) {
		return;
	}

	ifp = group->interface;
	pim_ifp = ifp->info;
	ifname = ifp->name;

	lmqi_dsec = pim_ifp->gm_specific_query_max_response_time_dsec;
	lmqc = pim_ifp->gm_last_member_query_count;
	lmqt_msec = PIM_IGMP_LMQT_MSEC(
		lmqi_dsec, lmqc); /* lmqt_msec = (100 * lmqi_dsec) * lmqc */

	if (PIM_DEBUG_GM_TRACE) {
		char group_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<group?>", group->group_addr, group_str,
			       sizeof(group_str));
		zlog_debug(
			"%s: group %s on %s: LMQC=%d LMQI=%d dsec LMQT=%d msec",
			__func__, group_str, ifname, lmqc, lmqi_dsec,
			lmqt_msec);
	}

	assert(group->group_filtermode_isexcl);

	igmp_group_timer_on(group, lmqt_msec, ifname);
}

void igmp_source_timer_lower_to_lmqt(struct gm_source *source)
{
	struct gm_group *group;
	struct interface *ifp;
	struct pim_interface *pim_ifp;
	char *ifname;
	int lmqi_dsec; /* Last Member Query Interval */
	int lmqc;      /* Last Member Query Count */
	int lmqt_msec; /* Last Member Query Time */

	group = source->source_group;
	ifp = group->interface;
	pim_ifp = ifp->info;
	ifname = ifp->name;

	lmqi_dsec = pim_ifp->gm_specific_query_max_response_time_dsec;
	lmqc = pim_ifp->gm_last_member_query_count;
	lmqt_msec = PIM_IGMP_LMQT_MSEC(
		lmqi_dsec, lmqc); /* lmqt_msec = (100 * lmqi_dsec) * lmqc */

	if (PIM_DEBUG_GM_TRACE) {
		char group_str[INET_ADDRSTRLEN];
		char source_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<group?>", group->group_addr, group_str,
			       sizeof(group_str));
		pim_inet4_dump("<source?>", source->source_addr, source_str,
			       sizeof(source_str));
		zlog_debug(
			"%s: group %s source %s on %s: LMQC=%d LMQI=%d dsec LMQT=%d msec",
			__func__, group_str, source_str, ifname, lmqc,
			lmqi_dsec, lmqt_msec);
	}

	igmp_source_timer_on(group, source, lmqt_msec);
}

void igmp_v3_send_query(struct gm_group *group, int fd, const char *ifname,
			char *query_buf, int query_buf_size, int num_sources,
			struct in_addr dst_addr, struct in_addr group_addr,
			int query_max_response_time_dsec, uint8_t s_flag,
			uint8_t querier_robustness_variable,
			uint16_t querier_query_interval)
{
	ssize_t msg_size;
	uint8_t max_resp_code;
	uint8_t qqic;
	ssize_t sent;
	struct sockaddr_in to;
	socklen_t tolen;
	uint16_t checksum;

	assert(num_sources >= 0);

	msg_size = IGMP_V3_SOURCES_OFFSET + (num_sources << 2);
	if (msg_size > query_buf_size) {
		flog_err(
			EC_LIB_DEVELOPMENT,
			"%s %s: unable to send: msg_size=%zd larger than query_buf_size=%d",
			__FILE__, __func__, msg_size, query_buf_size);
		return;
	}

	s_flag = PIM_FORCE_BOOLEAN(s_flag);
	assert((s_flag == 0) || (s_flag == 1));

	max_resp_code = igmp_msg_encode16to8(query_max_response_time_dsec);
	qqic = igmp_msg_encode16to8(querier_query_interval);

	/*
	  RFC 3376: 4.1.6. QRV (Querier's Robustness Variable)

	  If non-zero, the QRV field contains the [Robustness Variable]
	  value used by the querier, i.e., the sender of the Query.  If the
	  querier's [Robustness Variable] exceeds 7, the maximum value of
	  the QRV field, the QRV is set to zero.
	*/
	if (querier_robustness_variable > 7) {
		querier_robustness_variable = 0;
	}

	query_buf[0] = PIM_IGMP_MEMBERSHIP_QUERY;
	query_buf[1] = max_resp_code;
	*(uint16_t *)(query_buf + IGMP_CHECKSUM_OFFSET) =
		0; /* for computing checksum */
	memcpy(query_buf + 4, &group_addr, sizeof(struct in_addr));

	query_buf[8] = (s_flag << 3) | querier_robustness_variable;
	query_buf[9] = qqic;
	*(uint16_t *)(query_buf + IGMP_V3_NUMSOURCES_OFFSET) =
		htons(num_sources);

	checksum = in_cksum(query_buf, msg_size);
	*(uint16_t *)(query_buf + IGMP_CHECKSUM_OFFSET) = checksum;

	if (PIM_DEBUG_GM_PACKETS) {
		char dst_str[INET_ADDRSTRLEN];
		char group_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<dst?>", dst_addr, dst_str, sizeof(dst_str));
		pim_inet4_dump("<group?>", group_addr, group_str,
			       sizeof(group_str));
		zlog_debug(
			"Send IGMPv3 query to %s on %s for group %s, sources=%d msg_size=%zd s_flag=%x QRV=%u QQI=%u QQIC=%02x",
			dst_str, ifname, group_str, num_sources, msg_size,
			s_flag, querier_robustness_variable,
			querier_query_interval, qqic);
	}

	memset(&to, 0, sizeof(to));
	to.sin_family = AF_INET;
	to.sin_addr = dst_addr;
	tolen = sizeof(to);

	sent = sendto(fd, query_buf, msg_size, MSG_DONTWAIT,
		      (struct sockaddr *)&to, tolen);
	if (sent != (ssize_t)msg_size) {
		char dst_str[INET_ADDRSTRLEN];
		char group_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<dst?>", dst_addr, dst_str, sizeof(dst_str));
		pim_inet4_dump("<group?>", group_addr, group_str,
			       sizeof(group_str));
		if (sent < 0) {
			zlog_warn(
				"Send IGMPv3 query failed due to %s on %s: group=%s msg_size=%zd: errno=%d: %s",
				dst_str, ifname, group_str, msg_size, errno,
				safe_strerror(errno));
		} else {
			zlog_warn(
				"Send IGMPv3 query failed due to %s on %s: group=%s msg_size=%zd: sent=%zd",
				dst_str, ifname, group_str, msg_size, sent);
		}
		return;
	}

	/*
	  s_flag sanity test: s_flag must be set for general queries

	  RFC 3376: 6.6.1. Timer Updates

	  When a router sends or receives a query with a clear Suppress
	  Router-Side Processing flag, it must update its timers to reflect
	  the correct timeout values for the group or sources being queried.

	  General queries don't trigger timer update.
	*/
	if (!s_flag) {
		/* general query? */
		if (group_addr.s_addr == INADDR_ANY) {
			char dst_str[INET_ADDRSTRLEN];
			char group_str[INET_ADDRSTRLEN];
			pim_inet4_dump("<dst?>", dst_addr, dst_str,
				       sizeof(dst_str));
			pim_inet4_dump("<group?>", group_addr, group_str,
				       sizeof(group_str));
			zlog_warn(
				"%s: to %s on %s: group=%s sources=%d: s_flag is clear for general query!",
				__func__, dst_str, ifname, group_str,
				num_sources);
		}
	}
}

void igmp_v3_recv_query(struct gm_sock *igmp, const char *from_str,
			char *igmp_msg)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;
	struct in_addr group_addr;
	uint8_t resv_s_qrv = 0;
	uint8_t s_flag = 0;
	uint8_t qrv = 0;
	int i;

	memcpy(&group_addr, igmp_msg + 4, sizeof(struct in_addr));
	ifp = igmp->interface;
	pim_ifp = ifp->info;

	/*
	 * RFC 3376: 4.1.6. QRV (Querier's Robustness Variable)
	 *
	 * Routers adopt the QRV value from the most recently received Query
	 * as their own [Robustness Variable] value, unless that most
	 * recently received QRV was zero, in which case the receivers use
	 * the default [Robustness Variable] value specified in section 8.1
	 * or a statically configured value.
	 */
	resv_s_qrv = igmp_msg[8];
	qrv = 7 & resv_s_qrv;
	igmp->querier_robustness_variable =
		qrv ? qrv : pim_ifp->gm_default_robustness_variable;

	/*
	 * RFC 3376: 4.1.7. QQIC (Querier's Query Interval Code)
	 *
	 * Multicast routers that are not the current querier adopt the QQI
	 * value from the most recently received Query as their own [Query
	 * Interval] value, unless that most recently received QQI was zero,
	 * in which case the receiving routers use the default.
	 */
	if (igmp->t_other_querier_timer) {
		/* other querier present */
		uint8_t qqic;
		uint16_t qqi;
		qqic = igmp_msg[9];
		qqi = igmp_msg_decode8to16(qqic);
		igmp->querier_query_interval =
			qqi ? qqi : pim_ifp->gm_default_query_interval;

		if (PIM_DEBUG_GM_TRACE) {
			char ifaddr_str[INET_ADDRSTRLEN];
			pim_inet4_dump("<ifaddr?>", igmp->ifaddr, ifaddr_str,
				       sizeof(ifaddr_str));
			zlog_debug(
				"Querier %s new query interval is %s QQI=%u sec (recv QQIC=%02x from %s)",
				ifaddr_str,
				qqi ? "recv-non-default" : "default",
				igmp->querier_query_interval, qqic, from_str);
		}
	}

	/*
	 * RFC 3376: 6.6.1. Timer Updates
	 *
	 * When a router sends or receives a query with a clear Suppress
	 * Router-Side Processing flag, it must update its timers to reflect
	 * the correct timeout values for the group or sources being queried.
	 *
	 * General queries don't trigger timer update.
	 */
	s_flag = (1 << 3) & resv_s_qrv;

	if (!s_flag) {
		/* s_flag is clear */

		if (group_addr.s_addr == INADDR_ANY) {
			/* this is a general query */
			/* log that general query should have the s_flag set */
			zlog_warn(
				"General IGMP query v3 from %s on %s: Suppress Router-Side Processing flag is clear",
				from_str, ifp->name);
		} else {
			struct gm_group *group;

			/* this is a non-general query: perform timer updates */

			group = find_group_by_addr(igmp, group_addr);
			if (group) {
				int recv_num_sources = ntohs(*(
					uint16_t
						*)(igmp_msg
						   + IGMP_V3_NUMSOURCES_OFFSET));

				/*
				 * RFC 3376: 6.6.1. Timer Updates
				 * Query Q(G,A): Source Timer for sources in A
				 * are lowered to LMQT
				 * Query Q(G): Group Timer is lowered to LMQT
				 */
				if (recv_num_sources < 1) {
					/* Query Q(G): Group Timer is lowered to
					 * LMQT */

					igmp_group_timer_lower_to_lmqt(group);
				} else {
					/* Query Q(G,A): Source Timer for
					 * sources in A are lowered to LMQT */

					/* Scan sources in query and lower their
					 * timers to LMQT */
					struct in_addr *sources =
						(struct in_addr
							 *)(igmp_msg
							    + IGMP_V3_SOURCES_OFFSET);
					for (i = 0; i < recv_num_sources; ++i) {
						struct in_addr src_addr;
						struct gm_source *src;
						memcpy(&src_addr, sources + i,
						       sizeof(struct in_addr));
						src = igmp_find_source_by_addr(
							group, src_addr);
						if (src) {
							igmp_source_timer_lower_to_lmqt(
								src);
						}
					}
				}
			} else {
				char group_str[INET_ADDRSTRLEN];
				pim_inet4_dump("<group?>", group_addr,
					       group_str, sizeof(group_str));
				zlog_warn(
					"IGMP query v3 from %s on %s: could not find group %s for timer update",
					from_str, ifp->name, group_str);
			}
		}
	} /* s_flag is clear: timer updates */
}

static bool igmp_pkt_grp_addr_ok(struct interface *ifp, const char *from_str,
				 struct in_addr grp, int rec_type)
{
	struct pim_interface *pim_ifp;
	struct in_addr grp_addr;

	pim_ifp = ifp->info;

	/* determine filtering status for group */
	if (pim_is_group_filtered(pim_ifp, &grp)) {
		if (PIM_DEBUG_GM_PACKETS) {
			zlog_debug(
				"Filtering IGMPv3 group record %pI4 from %s on %s per prefix-list %s",
				&grp.s_addr, from_str, ifp->name,
				pim_ifp->boundary_oil_plist);
		}
		return false;
	}

	/*
	 * If we receive a igmp report with the group in 224.0.0.0/24
	 * then we should ignore it
	 */

	grp_addr.s_addr = ntohl(grp.s_addr);

	if (pim_is_group_224_0_0_0_24(grp_addr)) {
		if (PIM_DEBUG_GM_PACKETS) {
			zlog_debug(
				"Ignoring IGMPv3 group record %pI4 from %s on %s group range falls in 224.0.0.0/24",
				&grp.s_addr, from_str, ifp->name);
		}
		return false;
	}

	/*
	 * RFC 4604
	 * section 2.2.1
	 * EXCLUDE mode does not apply to SSM addresses, and an SSM-aware router
	 * will ignore MODE_IS_EXCLUDE and CHANGE_TO_EXCLUDE_MODE requests in
	 * the SSM range.
	 */
	if (pim_is_grp_ssm(pim_ifp->pim, grp)) {
		switch (rec_type) {
		case IGMP_GRP_REC_TYPE_MODE_IS_EXCLUDE:
		case IGMP_GRP_REC_TYPE_CHANGE_TO_EXCLUDE_MODE:
			if (PIM_DEBUG_GM_PACKETS) {
				zlog_debug(
					"Ignoring IGMPv3 group record %pI4 from %s on %s exclude mode in SSM range",
					&grp.s_addr, from_str, ifp->name);
			}
			return false;
		}
	}

	return true;
}

int igmp_v3_recv_report(struct gm_sock *igmp, struct in_addr from,
			const char *from_str, char *igmp_msg, int igmp_msg_len)
{
	int num_groups;
	uint8_t *group_record;
	uint8_t *report_pastend = (uint8_t *)igmp_msg + igmp_msg_len;
	struct interface *ifp = igmp->interface;
	struct pim_interface *pim_ifp = ifp->info;
	int i;

	if (igmp->mtrace_only)
		return 0;

	if (igmp_msg_len < IGMP_V3_MSG_MIN_SIZE) {
		zlog_warn(
			"Recv IGMP report v3 from %s on %s: size=%d shorter than minimum=%d",
			from_str, ifp->name, igmp_msg_len,
			IGMP_V3_MSG_MIN_SIZE);
		return -1;
	}

	if (igmp_validate_checksum(igmp_msg, igmp_msg_len) == -1) {
		zlog_warn(
			"Recv IGMPv3 report from %s on %s with invalid checksum",
			from_str, ifp->name);
		return -1;
	}

	/* Collecting IGMP Rx stats */
	igmp->igmp_stats.report_v3++;

	if (pim_ifp->igmp_version == 2) {
		zlog_warn(
			"Received Version 3 packet but interface: %s is configured for version 2",
			ifp->name);
		return -1;
	}

	num_groups = ntohs(
		*(uint16_t *)(igmp_msg + IGMP_V3_REPORT_NUMGROUPS_OFFSET));
	if (num_groups < 1) {
		zlog_warn(
			"Recv IGMP report v3 from %s on %s: missing group records",
			from_str, ifp->name);
		return -1;
	}

	if (PIM_DEBUG_GM_PACKETS) {
		zlog_debug(
			"Recv IGMP report v3 from %s on %s: size=%d groups=%d",
			from_str, ifp->name, igmp_msg_len, num_groups);
	}

	group_record = (uint8_t *)igmp_msg + IGMP_V3_REPORT_GROUPPRECORD_OFFSET;

	/* Scan groups */
	for (i = 0; i < num_groups; ++i) {
		struct in_addr rec_group;
		uint8_t *sources;
		uint8_t *src;
		int rec_type;
		int rec_auxdatalen;
		int rec_num_sources;
		int j;

		if ((group_record + IGMP_V3_GROUP_RECORD_MIN_SIZE)
		    > report_pastend) {
			zlog_warn(
				"Recv IGMP report v3 from %s on %s: group record beyond report end",
				from_str, ifp->name);
			return -1;
		}

		rec_type = group_record[IGMP_V3_GROUP_RECORD_TYPE_OFFSET];
		rec_auxdatalen =
			group_record[IGMP_V3_GROUP_RECORD_AUXDATALEN_OFFSET];
		rec_num_sources = ntohs(*(
			uint16_t *)(group_record
				    + IGMP_V3_GROUP_RECORD_NUMSOURCES_OFFSET));

		memcpy(&rec_group,
		       group_record + IGMP_V3_GROUP_RECORD_GROUP_OFFSET,
		       sizeof(struct in_addr));

		if (PIM_DEBUG_GM_PACKETS) {
			zlog_debug(
				"    Recv IGMP report v3 from %s on %s: record=%d type=%d auxdatalen=%d sources=%d group=%pI4",
				from_str, ifp->name, i, rec_type,
				rec_auxdatalen, rec_num_sources,
				&rec_group);
		}

		/* Scan sources */

		sources = group_record + IGMP_V3_GROUP_RECORD_SOURCE_OFFSET;

		for (j = 0, src = sources; j < rec_num_sources; ++j, src += 4) {

			if ((src + 4) > report_pastend) {
				zlog_warn(
					"Recv IGMP report v3 from %s on %s: group source beyond report end",
					from_str, ifp->name);
				return -1;
			}

			if (PIM_DEBUG_GM_PACKETS) {
				char src_str[200];

				if (!inet_ntop(AF_INET, src, src_str,
					       sizeof(src_str)))
					snprintf(src_str, sizeof(src_str),
						 "<source?>");

				zlog_debug(
					"        Recv IGMP report v3 from %s on %s: record=%d group=%pI4 source=%s",
					from_str, ifp->name, i,
					&rec_group, src_str);
			}
		} /* for (sources) */


		if (igmp_pkt_grp_addr_ok(ifp, from_str, rec_group, rec_type))
			switch (rec_type) {
			case IGMP_GRP_REC_TYPE_MODE_IS_INCLUDE:
				igmpv3_report_isin(igmp, from, rec_group,
						   rec_num_sources,
						   (struct in_addr *)sources);
				break;
			case IGMP_GRP_REC_TYPE_MODE_IS_EXCLUDE:
				igmpv3_report_isex(
					igmp, from, rec_group, rec_num_sources,
					(struct in_addr *)sources, 0);
				break;
			case IGMP_GRP_REC_TYPE_CHANGE_TO_INCLUDE_MODE:
				igmpv3_report_toin(igmp, from, rec_group,
						   rec_num_sources,
						   (struct in_addr *)sources);
				break;
			case IGMP_GRP_REC_TYPE_CHANGE_TO_EXCLUDE_MODE:
				igmpv3_report_toex(igmp, from, rec_group,
						   rec_num_sources,
						   (struct in_addr *)sources);
				break;
			case IGMP_GRP_REC_TYPE_ALLOW_NEW_SOURCES:
				igmpv3_report_allow(igmp, from, rec_group,
						    rec_num_sources,
						    (struct in_addr *)sources);
				break;
			case IGMP_GRP_REC_TYPE_BLOCK_OLD_SOURCES:
				igmpv3_report_block(igmp, from, rec_group,
						    rec_num_sources,
						    (struct in_addr *)sources);
				break;
			default:
				zlog_warn(
					"Recv IGMP report v3 from %s on %s: unknown record type: type=%d",
					from_str, ifp->name, rec_type);
			}

		group_record +=
			8 + (rec_num_sources << 2) + (rec_auxdatalen << 2);

	} /* for (group records) */

	return 0;
}
