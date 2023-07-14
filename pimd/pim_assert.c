// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 */

#include <zebra.h>

#include "log.h"
#include "prefix.h"
#include "if.h"

#include "pimd.h"
#include "pim_instance.h"
#include "pim_str.h"
#include "pim_tlv.h"
#include "pim_msg.h"
#include "pim_pim.h"
#include "pim_int.h"
#include "pim_time.h"
#include "pim_iface.h"
#include "pim_hello.h"
#include "pim_macro.h"
#include "pim_assert.h"
#include "pim_zebra.h"
#include "pim_ifchannel.h"

static int assert_action_a3(struct pim_ifchannel *ch);
static void assert_action_a2(struct pim_ifchannel *ch,
			     struct pim_assert_metric winner_metric);
static void assert_action_a6(struct pim_ifchannel *ch,
			     struct pim_assert_metric winner_metric);

void pim_ifassert_winner_set(struct pim_ifchannel *ch,
			     enum pim_ifassert_state new_state, pim_addr winner,
			     struct pim_assert_metric winner_metric)
{
	struct pim_interface *pim_ifp = ch->interface->info;
	int winner_changed = !!pim_addr_cmp(ch->ifassert_winner, winner);
	int metric_changed = !pim_assert_metric_match(
		&ch->ifassert_winner_metric, &winner_metric);
	enum pim_rpf_result rpf_result;
	struct pim_rpf old_rpf;

	if (PIM_DEBUG_PIM_EVENTS) {
		if (ch->ifassert_state != new_state) {
			zlog_debug(
				"%s: (S,G)=%s assert state changed from %s to %s on interface %s",
				__func__, ch->sg_str,
				pim_ifchannel_ifassert_name(ch->ifassert_state),
				pim_ifchannel_ifassert_name(new_state),
				ch->interface->name);
		}

		if (winner_changed)
			zlog_debug(
				"%s: (S,G)=%s assert winner changed from %pPAs to %pPAs on interface %s",
				__func__, ch->sg_str, &ch->ifassert_winner,
				&winner, ch->interface->name);
	} /* PIM_DEBUG_PIM_EVENTS */

	ch->ifassert_state = new_state;
	ch->ifassert_winner = winner;
	ch->ifassert_winner_metric = winner_metric;
	ch->ifassert_creation = pim_time_monotonic_sec();

	if (winner_changed || metric_changed) {
		if (winner_changed) {
			old_rpf.source_nexthop.interface =
				ch->upstream->rpf.source_nexthop.interface;
			rpf_result = pim_rpf_update(pim_ifp->pim, ch->upstream,
						    &old_rpf, __func__);
			if (rpf_result == PIM_RPF_CHANGED ||
			    (rpf_result == PIM_RPF_FAILURE &&
			     old_rpf.source_nexthop.interface))
				pim_zebra_upstream_rpf_changed(
					pim_ifp->pim, ch->upstream, &old_rpf);
			/* update kernel multicast forwarding cache (MFC) */
			if (ch->upstream->rpf.source_nexthop.interface &&
			    ch->upstream->channel_oil)
				pim_upstream_mroute_iif_update(
					ch->upstream->channel_oil, __func__);
		}
		pim_upstream_update_join_desired(pim_ifp->pim, ch->upstream);
		pim_ifchannel_update_could_assert(ch);
		pim_ifchannel_update_assert_tracking_desired(ch);
	}
}

static void on_trace(const char *label, struct interface *ifp, pim_addr src)
{
	if (PIM_DEBUG_PIM_TRACE)
		zlog_debug("%s: from %pPAs on %s", label, &src, ifp->name);
}

static int preferred_assert(const struct pim_ifchannel *ch,
			    const struct pim_assert_metric *recv_metric)
{
	return pim_assert_metric_better(recv_metric,
					&ch->ifassert_winner_metric);
}

static int acceptable_assert(const struct pim_assert_metric *my_metric,
			     const struct pim_assert_metric *recv_metric)
{
	return pim_assert_metric_better(recv_metric, my_metric);
}

static int inferior_assert(const struct pim_assert_metric *my_metric,
			   const struct pim_assert_metric *recv_metric)
{
	return pim_assert_metric_better(my_metric, recv_metric);
}

static int cancel_assert(const struct pim_assert_metric *recv_metric)
{
	return (recv_metric->metric_preference
		== PIM_ASSERT_METRIC_PREFERENCE_MAX)
	       && (recv_metric->route_metric == PIM_ASSERT_ROUTE_METRIC_MAX);
}

static void if_could_assert_do_a1(const char *caller, struct pim_ifchannel *ch)
{
	if (PIM_IF_FLAG_TEST_COULD_ASSERT(ch->flags)) {
		if (assert_action_a1(ch)) {
			zlog_warn(
				"%s: %s: (S,G)=%s assert_action_a1 failure on interface %s",
				__func__, caller, ch->sg_str,
				ch->interface->name);
			/* log warning only */
		}
	}
}

static int dispatch_assert(struct interface *ifp, pim_addr source_addr,
			   pim_addr group_addr,
			   struct pim_assert_metric recv_metric)
{
	struct pim_ifchannel *ch;
	pim_sgaddr sg;

	memset(&sg, 0, sizeof(sg));
	sg.src = source_addr;
	sg.grp = group_addr;
	ch = pim_ifchannel_add(ifp, &sg, 0, 0);

	switch (ch->ifassert_state) {
	case PIM_IFASSERT_NOINFO:
		if (recv_metric.rpt_bit_flag) {
			/* RPT bit set */
			if_could_assert_do_a1(__func__, ch);
		} else {
			/* RPT bit clear */
			if (inferior_assert(&ch->ifassert_my_metric,
					    &recv_metric)) {
				if_could_assert_do_a1(__func__, ch);
			} else if (acceptable_assert(&ch->ifassert_my_metric,
						     &recv_metric)) {
				if (PIM_IF_FLAG_TEST_ASSERT_TRACKING_DESIRED(
					    ch->flags)) {
					assert_action_a6(ch, recv_metric);
				}
			}
		}
		break;
	case PIM_IFASSERT_I_AM_WINNER:
		if (preferred_assert(ch, &recv_metric)) {
			assert_action_a2(ch, recv_metric);
		} else {
			if (inferior_assert(&ch->ifassert_my_metric,
					    &recv_metric)) {
				assert_action_a3(ch);
			}
		}
		break;
	case PIM_IFASSERT_I_AM_LOSER:
		if (!pim_addr_cmp(recv_metric.ip_address,
				  ch->ifassert_winner)) {
			/* Assert from current winner */

			if (cancel_assert(&recv_metric)) {
				assert_action_a5(ch);
			} else {
				if (inferior_assert(&ch->ifassert_my_metric,
						    &recv_metric)) {
					assert_action_a5(ch);
				} else if (acceptable_assert(
						   &ch->ifassert_my_metric,
						   &recv_metric)) {
					if (!recv_metric.rpt_bit_flag) {
						assert_action_a2(ch,
								 recv_metric);
					}
				}
			}
		} else if (preferred_assert(ch, &recv_metric)) {
			assert_action_a2(ch, recv_metric);
		}
		break;
	default: {
		zlog_warn(
			"%s: (S,G)=%s invalid assert state %d on interface %s",
			__func__, ch->sg_str, ch->ifassert_state, ifp->name);
	}
		return -2;
	}

	return 0;
}

int pim_assert_recv(struct interface *ifp, struct pim_neighbor *neigh,
		    pim_addr src_addr, uint8_t *buf, int buf_size)
{
	pim_sgaddr sg;
	pim_addr msg_source_addr;
	bool wrong_af = false;
	struct pim_assert_metric msg_metric;
	int offset;
	uint8_t *curr;
	int curr_size;
	struct pim_interface *pim_ifp = NULL;

	on_trace(__func__, ifp, src_addr);

	curr = buf;
	curr_size = buf_size;

	/*
	  Parse assert group addr
	 */
	memset(&sg, 0, sizeof(sg));
	offset = pim_parse_addr_group(&sg, curr, curr_size);
	if (offset < 1) {
		zlog_warn(
			"%s: pim_parse_addr_group() failure: from %pPAs on %s",
			__func__, &src_addr, ifp->name);
		return -1;
	}
	curr += offset;
	curr_size -= offset;

	/*
	  Parse assert source addr
	*/
	offset = pim_parse_addr_ucast(&msg_source_addr, curr, curr_size,
				      &wrong_af);
	if (offset < 1 || wrong_af) {
		zlog_warn(
			"%s: pim_parse_addr_ucast() failure: from %pPAs on %s",
			__func__, &src_addr, ifp->name);
		return -2;
	}
	curr += offset;
	curr_size -= offset;

	if (curr_size < 8) {
		zlog_warn(
			"%s: preference/metric size is less than 8 bytes: size=%d from %pPAs on interface %s",
			__func__, curr_size, &src_addr, ifp->name);
		return -3;
	}

	/*
	  Parse assert metric preference
	*/

	msg_metric.metric_preference = pim_read_uint32_host(curr);

	msg_metric.rpt_bit_flag = msg_metric.metric_preference
				  & 0x80000000;      /* save highest bit */
	msg_metric.metric_preference &= ~0x80000000; /* clear highest bit */

	curr += 4;

	/*
	  Parse assert route metric
	*/

	msg_metric.route_metric = pim_read_uint32_host(curr);

	if (PIM_DEBUG_PIM_TRACE)
		zlog_debug(
			"%s: from %pPAs on %s: (S,G)=(%pPAs,%pPAs) pref=%u metric=%u rpt_bit=%u",
			__func__, &src_addr, ifp->name, &msg_source_addr,
			&sg.grp, msg_metric.metric_preference,
			msg_metric.route_metric,
			PIM_FORCE_BOOLEAN(msg_metric.rpt_bit_flag));

	msg_metric.ip_address = src_addr;

	pim_ifp = ifp->info;
	assert(pim_ifp);

	if (pim_ifp->pim_passive_enable) {
		if (PIM_DEBUG_PIM_PACKETS)
			zlog_debug(
				"skip receiving PIM message on passive interface %s",
				ifp->name);
		return 0;
	}

	++pim_ifp->pim_ifstat_assert_recv;

	return dispatch_assert(ifp, msg_source_addr, sg.grp, msg_metric);
}

/*
  RFC 4601: 4.6.3.  Assert Metrics

   Assert metrics are defined as:

   When comparing assert_metrics, the rpt_bit_flag, metric_preference,
   and route_metric field are compared in order, where the first lower
   value wins.  If all fields are equal, the primary IP address of the
   router that sourced the Assert message is used as a tie-breaker,
   with the highest IP address winning.
*/
int pim_assert_metric_better(const struct pim_assert_metric *m1,
			     const struct pim_assert_metric *m2)
{
	if (m1->rpt_bit_flag < m2->rpt_bit_flag)
		return 1;
	if (m1->rpt_bit_flag > m2->rpt_bit_flag)
		return 0;

	if (m1->metric_preference < m2->metric_preference)
		return 1;
	if (m1->metric_preference > m2->metric_preference)
		return 0;

	if (m1->route_metric < m2->route_metric)
		return 1;
	if (m1->route_metric > m2->route_metric)
		return 0;

	return pim_addr_cmp(m1->ip_address, m2->ip_address) > 0;
}

int pim_assert_metric_match(const struct pim_assert_metric *m1,
			    const struct pim_assert_metric *m2)
{
	if (m1->rpt_bit_flag != m2->rpt_bit_flag)
		return 0;
	if (m1->metric_preference != m2->metric_preference)
		return 0;
	if (m1->route_metric != m2->route_metric)
		return 0;

	return !pim_addr_cmp(m1->ip_address, m2->ip_address);
}

int pim_assert_build_msg(uint8_t *pim_msg, int buf_size, struct interface *ifp,
			 pim_addr group_addr, pim_addr source_addr,
			 uint32_t metric_preference, uint32_t route_metric,
			 uint32_t rpt_bit_flag)
{
	struct pim_interface *pim_ifp = ifp->info;
	uint8_t *buf_pastend = pim_msg + buf_size;
	uint8_t *pim_msg_curr;
	int pim_msg_size;
	int remain;

	pim_msg_curr =
		pim_msg + PIM_MSG_HEADER_LEN; /* skip room for pim header */

	/* Encode group */
	remain = buf_pastend - pim_msg_curr;
	pim_msg_curr = pim_msg_addr_encode_group(pim_msg_curr, group_addr);
	if (!pim_msg_curr) {
		zlog_warn(
			"%s: failure encoding group address %pPA: space left=%d",
			__func__, &group_addr, remain);
		return -1;
	}

	/* Encode source */
	remain = buf_pastend - pim_msg_curr;
	pim_msg_curr = pim_msg_addr_encode_ucast(pim_msg_curr, source_addr);
	if (!pim_msg_curr) {
		zlog_warn(
			"%s: failure encoding source address %pPA: space left=%d",
			__func__, &source_addr, remain);
		return -2;
	}

	/* Metric preference */
	pim_write_uint32(pim_msg_curr,
			 rpt_bit_flag ? metric_preference | 0x80000000
				      : metric_preference);
	pim_msg_curr += 4;

	/* Route metric */
	pim_write_uint32(pim_msg_curr, route_metric);
	pim_msg_curr += 4;

	/*
	  Add PIM header
	*/
	pim_msg_size = pim_msg_curr - pim_msg;
	pim_msg_build_header(pim_ifp->primary_address,
			     qpim_all_pim_routers_addr, pim_msg, pim_msg_size,
			     PIM_MSG_TYPE_ASSERT, false);

	return pim_msg_size;
}

static int pim_assert_do(struct pim_ifchannel *ch,
			 struct pim_assert_metric metric)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;
	uint8_t pim_msg[1000];
	int pim_msg_size;

	ifp = ch->interface;
	if (!ifp) {
		if (PIM_DEBUG_PIM_TRACE)
			zlog_debug("%s: channel%s has no associated interface!",
				   __func__, ch->sg_str);
		return -1;
	}
	pim_ifp = ifp->info;
	if (!pim_ifp) {
		if (PIM_DEBUG_PIM_TRACE)
			zlog_debug(
				"%s: channel %s pim not enabled on interface: %s",
				__func__, ch->sg_str, ifp->name);
		return -1;
	}

	pim_msg_size =
		pim_assert_build_msg(pim_msg, sizeof(pim_msg), ifp, ch->sg.grp,
				     ch->sg.src, metric.metric_preference,
				     metric.route_metric, metric.rpt_bit_flag);
	if (pim_msg_size < 1) {
		zlog_warn(
			"%s: failure building PIM assert message: msg_size=%d",
			__func__, pim_msg_size);
		return -2;
	}

	/*
	  RFC 4601: 4.3.1.  Sending Hello Messages

	  Thus, if a router needs to send a Join/Prune or Assert message on
	  an interface on which it has not yet sent a Hello message with the
	  currently configured IP address, then it MUST immediately send the
	  relevant Hello message without waiting for the Hello Timer to
	  expire, followed by the Join/Prune or Assert message.
	*/
	pim_hello_require(ifp);

	if (PIM_DEBUG_PIM_TRACE) {
		zlog_debug("%s: to %s: (S,G)=%s pref=%u metric=%u rpt_bit=%u",
			   __func__, ifp->name, ch->sg_str,
			   metric.metric_preference, metric.route_metric,
			   PIM_FORCE_BOOLEAN(metric.rpt_bit_flag));
	}
	if (!pim_ifp->pim_passive_enable)
		++pim_ifp->pim_ifstat_assert_send;

	if (pim_msg_send(pim_ifp->pim_sock_fd, pim_ifp->primary_address,
			 qpim_all_pim_routers_addr, pim_msg, pim_msg_size,
			 ifp)) {
		zlog_warn("%s: could not send PIM message on interface %s",
			  __func__, ifp->name);
		return -3;
	}

	return 0;
}

int pim_assert_send(struct pim_ifchannel *ch)
{
	return pim_assert_do(ch, ch->ifassert_my_metric);
}

/*
  RFC 4601: 4.6.4.  AssertCancel Messages

  An AssertCancel(S,G) is an infinite metric assert with the RPT bit
  set that names S as the source.
 */
static int pim_assert_cancel(struct pim_ifchannel *ch)
{
	struct pim_assert_metric metric;

	metric.rpt_bit_flag = 0;
	metric.metric_preference = PIM_ASSERT_METRIC_PREFERENCE_MAX;
	metric.route_metric = PIM_ASSERT_ROUTE_METRIC_MAX;
	metric.ip_address = ch->sg.src;

	return pim_assert_do(ch, metric);
}

static void on_assert_timer(struct event *t)
{
	struct pim_ifchannel *ch;
	struct interface *ifp;

	ch = EVENT_ARG(t);

	ifp = ch->interface;

	if (PIM_DEBUG_PIM_TRACE) {
		zlog_debug("%s: (S,G)=%s timer expired on interface %s",
			   __func__, ch->sg_str, ifp->name);
	}

	ch->t_ifassert_timer = NULL;

	switch (ch->ifassert_state) {
	case PIM_IFASSERT_I_AM_WINNER:
		assert_action_a3(ch);
		break;
	case PIM_IFASSERT_I_AM_LOSER:
		assert_action_a5(ch);
		break;
	case PIM_IFASSERT_NOINFO: {
		if (PIM_DEBUG_PIM_EVENTS)
			zlog_warn(
				"%s: (S,G)=%s invalid assert state %d on interface %s",
				__func__, ch->sg_str, ch->ifassert_state,
				ifp->name);
	}
	}
}

static void assert_timer_off(struct pim_ifchannel *ch)
{
	if (PIM_DEBUG_PIM_TRACE) {
		if (ch->t_ifassert_timer) {
			zlog_debug(
				"%s: (S,G)=%s cancelling timer on interface %s",
				__func__, ch->sg_str, ch->interface->name);
		}
	}
	EVENT_OFF(ch->t_ifassert_timer);
}

static void pim_assert_timer_set(struct pim_ifchannel *ch, int interval)
{
	assert_timer_off(ch);

	if (PIM_DEBUG_PIM_TRACE) {
		zlog_debug("%s: (S,G)=%s starting %u sec timer on interface %s",
			   __func__, ch->sg_str, interval, ch->interface->name);
	}

	event_add_timer(router->master, on_assert_timer, ch, interval,
			&ch->t_ifassert_timer);
}

static void pim_assert_timer_reset(struct pim_ifchannel *ch)
{
	pim_assert_timer_set(ch,
			     PIM_ASSERT_TIME - PIM_ASSERT_OVERRIDE_INTERVAL);
}

/*
  RFC 4601: 4.6.1.  (S,G) Assert Message State Machine

  (S,G) Assert State machine Actions

  A1:  Send Assert(S,G).
  Set Assert Timer to (Assert_Time - Assert_Override_Interval).
  Store self as AssertWinner(S,G,I).
  Store spt_assert_metric(S,I) as AssertWinnerMetric(S,G,I).
*/
int assert_action_a1(struct pim_ifchannel *ch)
{
	struct interface *ifp = ch->interface;
	struct pim_interface *pim_ifp;

	pim_ifp = ifp->info;
	if (!pim_ifp) {
		zlog_warn("%s: (S,G)=%s multicast not enabled on interface %s",
			  __func__, ch->sg_str, ifp->name);
		return -1; /* must return since pim_ifp is used below */
	}

	/* Switch to I_AM_WINNER before performing action_a3 below */
	pim_ifassert_winner_set(
		ch, PIM_IFASSERT_I_AM_WINNER, pim_ifp->primary_address,
		pim_macro_spt_assert_metric(&ch->upstream->rpf,
					    pim_ifp->primary_address));

	if (assert_action_a3(ch)) {
		zlog_warn(
			"%s: (S,G)=%s assert_action_a3 failure on interface %s",
			__func__, ch->sg_str, ifp->name);
		/* warning only */
	}

	if (ch->ifassert_state != PIM_IFASSERT_I_AM_WINNER) {
		if (PIM_DEBUG_PIM_EVENTS)
			zlog_warn(
				"%s: channel%s not in expected PIM_IFASSERT_I_AM_WINNER state",
				__func__, ch->sg_str);
	}

	return 0;
}

/*
  RFC 4601: 4.6.1.  (S,G) Assert Message State Machine

  (S,G) Assert State machine Actions

     A2:  Store new assert winner as AssertWinner(S,G,I) and assert
	  winner metric as AssertWinnerMetric(S,G,I).
	  Set Assert Timer to Assert_Time.
*/
static void assert_action_a2(struct pim_ifchannel *ch,
			     struct pim_assert_metric winner_metric)
{
	pim_ifassert_winner_set(ch, PIM_IFASSERT_I_AM_LOSER,
				winner_metric.ip_address, winner_metric);

	pim_assert_timer_set(ch, PIM_ASSERT_TIME);

	if (ch->ifassert_state != PIM_IFASSERT_I_AM_LOSER) {
		if (PIM_DEBUG_PIM_EVENTS)
			zlog_warn(
				"%s: channel%s not in expected PIM_IFASSERT_I_AM_LOSER state",
				__func__, ch->sg_str);
	}
}

/*
  RFC 4601: 4.6.1.  (S,G) Assert Message State Machine

  (S,G) Assert State machine Actions

  A3:  Send Assert(S,G).
  Set Assert Timer to (Assert_Time - Assert_Override_Interval).
*/
static int assert_action_a3(struct pim_ifchannel *ch)
{
	if (ch->ifassert_state != PIM_IFASSERT_I_AM_WINNER) {
		if (PIM_DEBUG_PIM_EVENTS)
			zlog_warn(
				"%s: channel%s expected to be in PIM_IFASSERT_I_AM_WINNER state",
				__func__, ch->sg_str);
		return -1;
	}

	pim_assert_timer_reset(ch);

	if (pim_assert_send(ch)) {
		zlog_warn("%s: (S,G)=%s failure sending assert on interface %s",
			  __func__, ch->sg_str, ch->interface->name);
		return -1;
	}

	return 0;
}

/*
  RFC 4601: 4.6.1.  (S,G) Assert Message State Machine

  (S,G) Assert State machine Actions

     A4:  Send AssertCancel(S,G).
	  Delete assert info (AssertWinner(S,G,I) and
	  AssertWinnerMetric(S,G,I) will then return their default
	  values).
*/
void assert_action_a4(struct pim_ifchannel *ch)
{
	if (pim_assert_cancel(ch)) {
		zlog_warn("%s: failure sending AssertCancel%s on interface %s",
			  __func__, ch->sg_str, ch->interface->name);
		/* log warning only */
	}

	assert_action_a5(ch);

	if (ch->ifassert_state != PIM_IFASSERT_NOINFO) {
		if (PIM_DEBUG_PIM_EVENTS)
			zlog_warn(
				"%s: channel%s not in PIM_IFASSERT_NOINFO state as expected",
				__func__, ch->sg_str);
	}
}

/*
  RFC 4601: 4.6.1.  (S,G) Assert Message State Machine

  (S,G) Assert State machine Actions

  A5: Delete assert info (AssertWinner(S,G,I) and
  AssertWinnerMetric(S,G,I) will then return their default values).
*/
void assert_action_a5(struct pim_ifchannel *ch)
{
	reset_ifassert_state(ch);
	if (ch->ifassert_state != PIM_IFASSERT_NOINFO) {
		if (PIM_DEBUG_PIM_EVENTS)
			zlog_warn(
				"%s: channel%s not in PIM_IFSSERT_NOINFO state as expected",
				__func__, ch->sg_str);
	}
}

/*
  RFC 4601: 4.6.1.  (S,G) Assert Message State Machine

  (S,G) Assert State machine Actions

     A6:  Store new assert winner as AssertWinner(S,G,I) and assert
	  winner metric as AssertWinnerMetric(S,G,I).
	  Set Assert Timer to Assert_Time.
	  If (I is RPF_interface(S)) AND (UpstreamJPState(S,G) == true)
	  set SPTbit(S,G) to true.
*/
static void assert_action_a6(struct pim_ifchannel *ch,
			     struct pim_assert_metric winner_metric)
{
	assert_action_a2(ch, winner_metric);

	/*
	  If (I is RPF_interface(S)) AND (UpstreamJPState(S,G) == true) set
	  SPTbit(S,G) to true.
	*/
	if (ch->upstream->rpf.source_nexthop.interface == ch->interface)
		if (ch->upstream->join_state == PIM_UPSTREAM_JOINED)
			ch->upstream->sptbit = PIM_UPSTREAM_SPTBIT_TRUE;

	if (ch->ifassert_state != PIM_IFASSERT_I_AM_LOSER) {
		if (PIM_DEBUG_PIM_EVENTS)
			zlog_warn(
				"%s: channel%s not in PIM_IFASSERT_I_AM_LOSER state as expected",
				__func__, ch->sg_str);
	}
}
