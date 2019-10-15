/*
 * BFD daemon northbound implementation.
 *
 * Copyright (C) 2019 Network Device Education Foundation, Inc. ("NetDEF")
 *                    Rafael Zalamena
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA.
 */

#include <zebra.h>

#include "lib/log.h"
#include "lib/northbound.h"

#include "bfd.h"

/*
 * Helpers.
 */
static void bfd_session_get_key(bool mhop, const struct lyd_node *dnode,
				struct bfd_key *bk)
{
	const char *ifname = NULL, *vrfname = NULL;
	struct sockaddr_any psa, lsa;

	/* Required destination parameter. */
	strtosa(yang_dnode_get_string(dnode, "./dest-addr"), &psa);

	/* Get optional source address. */
	memset(&lsa, 0, sizeof(lsa));
	if (yang_dnode_exists(dnode, "./source-addr"))
		strtosa(yang_dnode_get_string(dnode, "./source-addr"), &lsa);

	/* Get optional interface and vrf names. */
	if (yang_dnode_exists(dnode, "./interface"))
		ifname = yang_dnode_get_string(dnode, "./interface");
	if (yang_dnode_exists(dnode, "./vrf"))
		vrfname = yang_dnode_get_string(dnode, "./vrf");

	/* Generate the corresponding key. */
	gen_bfd_key(bk, &psa, &lsa, mhop, ifname, vrfname);
}

static int bfd_session_create(enum nb_event event, const struct lyd_node *dnode,
			      union nb_resource *resource, bool mhop)
{
	struct bfd_session *bs;
	const char *ifname;
	struct bfd_key bk;
	struct in6_addr i6a;

	switch (event) {
	case NB_EV_VALIDATE:
		/*
		 * When `dest-addr` is IPv6 and link-local we must
		 * require interface name, otherwise we can't figure
		 * which interface to use to send the packets.
		 *
		 * `memset` `i6a` in case address is IPv4 or non
		 * link-local IPv6, it should also avoid static
		 * analyzer warning about unset memory read.
		 */
		memset(&i6a, 0, sizeof(i6a));
		yang_dnode_get_ipv6(&i6a, dnode, "./dest-addr");

		/*
		 * To support old FRR versions we must allow empty
		 * interface to be specified, however that should
		 * change in the future.
		 */
		if (yang_dnode_exists(dnode, "./interface"))
			ifname = yang_dnode_get_string(dnode, "./interface");
		else
			ifname = "";

		if (IN6_IS_ADDR_LINKLOCAL(&i6a) && strlen(ifname) == 0) {
			zlog_warn("%s: when using link-local you must specify "
				  "an interface.", __func__);
			return NB_ERR_VALIDATION;
		}
		break;

	case NB_EV_PREPARE:
		bfd_session_get_key(mhop, dnode, &bk);
		bs = bfd_key_lookup(bk);

		/* This session was already configured by another daemon. */
		if (bs != NULL) {
			/* Now it is configured also by CLI. */
			BFD_SET_FLAG(bs->flags, BFD_SESS_FLAG_CONFIG);
			bs->refcount++;

			resource->ptr = bs;
			break;
		}

		bs = bfd_session_new();
		if (bs == NULL)
			return NB_ERR_RESOURCE;

		/* Fill the session key. */
		bfd_session_get_key(mhop, dnode, &bs->key);

		/* Set configuration flags. */
		bs->refcount = 1;
		BFD_SET_FLAG(bs->flags, BFD_SESS_FLAG_CONFIG);
		if (mhop)
			BFD_SET_FLAG(bs->flags, BFD_SESS_FLAG_MH);
		if (bs->key.family == AF_INET6)
			BFD_SET_FLAG(bs->flags, BFD_SESS_FLAG_IPV6);

		resource->ptr = bs;
		break;

	case NB_EV_APPLY:
		bs = resource->ptr;

		/* Only attempt to registrate if freshly allocated. */
		if (bs->discrs.my_discr == 0 && bs_registrate(bs) == NULL)
			return NB_ERR_RESOURCE;

		nb_running_set_entry(dnode, bs);
		break;

	case NB_EV_ABORT:
		bs = resource->ptr;
		if (bs->refcount <= 1)
			bfd_session_free(resource->ptr);
		break;
	}

	return NB_OK;
}

static int bfd_session_destroy(enum nb_event event,
			       const struct lyd_node *dnode, bool mhop)
{
	struct bfd_session *bs;
	struct bfd_key bk;

	switch (event) {
	case NB_EV_VALIDATE:
		bfd_session_get_key(mhop, dnode, &bk);
		if (bfd_key_lookup(bk) == NULL)
			return NB_ERR_INCONSISTENCY;
		break;

	case NB_EV_PREPARE:
		/* NOTHING */
		break;

	case NB_EV_APPLY:
		bs = nb_running_unset_entry(dnode);
		/* CLI is not using this session anymore. */
		if (BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_CONFIG) == 0)
			break;

		BFD_UNSET_FLAG(bs->flags, BFD_SESS_FLAG_CONFIG);
		bs->refcount--;
		/* There are still daemons using it. */
		if (bs->refcount > 0)
			break;

		bfd_session_free(bs);
		break;

	case NB_EV_ABORT:
		/* NOTHING */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-bfdd:bfdd/bfd
 */
static int bfdd_bfd_create(enum nb_event event,
			   const struct lyd_node *dnode
			   __attribute__((__unused__)),
			   union nb_resource *resource
			   __attribute__((__unused__)))
{
	/* NOTHING */
	return NB_OK;
}

static int bfdd_bfd_destroy(enum nb_event event, const struct lyd_node *dnode)
{
	switch (event) {
	case NB_EV_VALIDATE:
		/* NOTHING */
		return NB_OK;

	case NB_EV_PREPARE:
		/* NOTHING */
		return NB_OK;

	case NB_EV_APPLY:
		bfd_sessions_remove_manual();
		break;

	case NB_EV_ABORT:
		/* NOTHING */
		return NB_OK;
	}

	return NB_OK;
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop
 */
static int bfdd_bfd_sessions_single_hop_create(enum nb_event event,
					       const struct lyd_node *dnode,
					       union nb_resource *resource)
{
	return bfd_session_create(event, dnode, resource, false);
}

static int bfdd_bfd_sessions_single_hop_destroy(enum nb_event event,
						const struct lyd_node *dnode)
{
	return bfd_session_destroy(event, dnode, false);
}

static const void *
bfdd_bfd_sessions_single_hop_get_next(const void *parent_list_entry
				      __attribute__((__unused__)),
				      const void *list_entry)
{
	return bfd_session_next(list_entry, false);
}

static int bfdd_bfd_sessions_single_hop_get_keys(const void *list_entry,
						 struct yang_list_keys *keys)
{
	const struct bfd_session *bs = list_entry;
	char dstbuf[INET6_ADDRSTRLEN];

	inet_ntop(bs->key.family, &bs->key.peer, dstbuf, sizeof(dstbuf));

	keys->num = 3;
	strlcpy(keys->key[0], dstbuf, sizeof(keys->key[0]));
	strlcpy(keys->key[1], bs->key.ifname, sizeof(keys->key[1]));
	strlcpy(keys->key[2], bs->key.vrfname, sizeof(keys->key[2]));

	return NB_OK;
}

static const void *
bfdd_bfd_sessions_single_hop_lookup_entry(const void *parent_list_entry
					  __attribute__((__unused__)),
					  const struct yang_list_keys *keys)
{
	const char *dest_addr = keys->key[0];
	const char *ifname = keys->key[1];
	const char *vrf = keys->key[2];
	struct sockaddr_any psa, lsa;
	struct bfd_key bk;

	strtosa(dest_addr, &psa);
	memset(&lsa, 0, sizeof(lsa));
	gen_bfd_key(&bk, &psa, &lsa, false, ifname, vrf);

	return bfd_key_lookup(bk);
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/source-addr
 */
static int bfdd_bfd_sessions_single_hop_source_addr_modify(
	enum nb_event event __attribute__((__unused__)),
	const struct lyd_node *dnode __attribute__((__unused__)),
	union nb_resource *resource __attribute__((__unused__)))
{
	return NB_OK;
}

static int bfdd_bfd_sessions_single_hop_source_addr_destroy(
	enum nb_event event __attribute__((__unused__)),
	const struct lyd_node *dnode __attribute__((__unused__)))
{
	return NB_OK;
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/detection-multiplier
 */
static int bfdd_bfd_sessions_single_hop_detection_multiplier_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource __attribute__((__unused__)))
{
	uint8_t detection_multiplier = yang_dnode_get_uint8(dnode, NULL);
	struct bfd_session *bs;

	switch (event) {
	case NB_EV_VALIDATE:
		break;

	case NB_EV_PREPARE:
		/* NOTHING */
		break;

	case NB_EV_APPLY:
		bs = nb_running_get_entry(dnode, NULL, true);
		bs->detect_mult = detection_multiplier;
		break;

	case NB_EV_ABORT:
		/* NOTHING */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/desired-transmission-interval
 */
static int bfdd_bfd_sessions_single_hop_desired_transmission_interval_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource __attribute__((__unused__)))
{
	uint32_t tx_interval = yang_dnode_get_uint32(dnode, NULL);
	struct bfd_session *bs;

	switch (event) {
	case NB_EV_VALIDATE:
		if (tx_interval < 10000 || tx_interval > 60000000)
			return NB_ERR_VALIDATION;
		break;

	case NB_EV_PREPARE:
		/* NOTHING */
		break;

	case NB_EV_APPLY:
		bs = nb_running_get_entry(dnode, NULL, true);
		if (tx_interval == bs->timers.desired_min_tx)
			return NB_OK;

		bs->timers.desired_min_tx = tx_interval;
		bfd_set_polling(bs);
		break;

	case NB_EV_ABORT:
		/* NOTHING */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/required-receive-interval
 */
static int bfdd_bfd_sessions_single_hop_required_receive_interval_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource __attribute__((__unused__)))
{
	uint32_t rx_interval = yang_dnode_get_uint32(dnode, NULL);
	struct bfd_session *bs;

	switch (event) {
	case NB_EV_VALIDATE:
		if (rx_interval < 10000 || rx_interval > 60000000)
			return NB_ERR_VALIDATION;
		break;

	case NB_EV_PREPARE:
		/* NOTHING */
		break;

	case NB_EV_APPLY:
		bs = nb_running_get_entry(dnode, NULL, true);
		if (rx_interval == bs->timers.required_min_rx)
			return NB_OK;

		bs->timers.required_min_rx = rx_interval;
		bfd_set_polling(bs);
		break;

	case NB_EV_ABORT:
		/* NOTHING */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/administrative-down
 */
static int bfdd_bfd_sessions_single_hop_administrative_down_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource __attribute__((__unused__)))
{
	bool shutdown = yang_dnode_get_bool(dnode, NULL);
	struct bfd_session *bs;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
		return NB_OK;

	case NB_EV_APPLY:
		break;

	case NB_EV_ABORT:
		return NB_OK;
	}

	bs = nb_running_get_entry(dnode, NULL, true);

	if (shutdown == false) {
		if (!BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_SHUTDOWN))
			return NB_OK;

		BFD_UNSET_FLAG(bs->flags, BFD_SESS_FLAG_SHUTDOWN);

		/* Change and notify state change. */
		bs->ses_state = PTM_BFD_DOWN;
		control_notify(bs);

		/* Enable all timers. */
		bfd_recvtimer_update(bs);
		bfd_xmttimer_update(bs, bs->xmt_TO);
		if (BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_ECHO)) {
			bfd_echo_recvtimer_update(bs);
			bfd_echo_xmttimer_update(bs, bs->echo_xmt_TO);
		}
	} else {
		if (BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_SHUTDOWN))
			return NB_OK;

		BFD_SET_FLAG(bs->flags, BFD_SESS_FLAG_SHUTDOWN);

		/* Disable all events. */
		bfd_recvtimer_delete(bs);
		bfd_echo_recvtimer_delete(bs);
		bfd_xmttimer_delete(bs);
		bfd_echo_xmttimer_delete(bs);

		/* Change and notify state change. */
		bs->ses_state = PTM_BFD_ADM_DOWN;
		control_notify(bs);

		ptm_bfd_snd(bs, 0);
	}

	return NB_OK;
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/echo-mode
 */
static int bfdd_bfd_sessions_single_hop_echo_mode_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource __attribute__((__unused__)))
{
	bool echo = yang_dnode_get_bool(dnode, NULL);
	struct bfd_session *bs;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
		return NB_OK;

	case NB_EV_APPLY:
		break;

	case NB_EV_ABORT:
		return NB_OK;
	}

	bs = nb_running_get_entry(dnode, NULL, true);

	if (echo == false) {
		if (!BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_ECHO))
			return NB_OK;

		BFD_UNSET_FLAG(bs->flags, BFD_SESS_FLAG_ECHO);
		ptm_bfd_echo_stop(bs);
	} else {
		if (BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_ECHO))
			return NB_OK;

		BFD_SET_FLAG(bs->flags, BFD_SESS_FLAG_ECHO);
		/* Apply setting immediately. */
		if (!BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_SHUTDOWN))
			bs_echo_timer_handler(bs);
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-bfdd:bfdd/bfd/sessions/single-hop/desired-echo-transmission-interval
 */
static int
bfdd_bfd_sessions_single_hop_desired_echo_transmission_interval_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource __attribute__((__unused__)))
{
	uint32_t echo_interval = yang_dnode_get_uint32(dnode, NULL);
	struct bfd_session *bs;

	switch (event) {
	case NB_EV_VALIDATE:
		if (echo_interval < 10000 || echo_interval > 60000000)
			return NB_ERR_VALIDATION;
		break;

	case NB_EV_PREPARE:
		/* NOTHING */
		break;

	case NB_EV_APPLY:
		bs = nb_running_get_entry(dnode, NULL, true);
		if (echo_interval == bs->timers.required_min_echo)
			return NB_OK;

		bs->timers.required_min_echo = echo_interval;
		break;

	case NB_EV_ABORT:
		/* NOTHING */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/local-discriminator
 */
static struct yang_data *
bfdd_bfd_sessions_single_hop_stats_local_discriminator_get_elem(
	const char *xpath, const void *list_entry)
{
	const struct bfd_session *bs = list_entry;

	return yang_data_new_uint32(xpath, bs->discrs.my_discr);
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/local-state
 */
static struct yang_data *
bfdd_bfd_sessions_single_hop_stats_local_state_get_elem(const char *xpath,
							const void *list_entry)
{
	const struct bfd_session *bs = list_entry;

	return yang_data_new_enum(xpath, bs->ses_state);
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/local-diagnostic
 */
static struct yang_data *
bfdd_bfd_sessions_single_hop_stats_local_diagnostic_get_elem(
	const char *xpath, const void *list_entry)
{
	const struct bfd_session *bs = list_entry;

	return yang_data_new_enum(xpath, bs->local_diag);
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/local-multiplier
 */
static struct yang_data *
bfdd_bfd_sessions_single_hop_stats_local_multiplier_get_elem(
	const char *xpath, const void *list_entry)
{
	const struct bfd_session *bs = list_entry;

	return yang_data_new_int8(xpath, bs->detect_mult);
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/remote-discriminator
 */
static struct yang_data *
bfdd_bfd_sessions_single_hop_stats_remote_discriminator_get_elem(
	const char *xpath, const void *list_entry)
{
	const struct bfd_session *bs = list_entry;

	if (bs->discrs.remote_discr == 0)
		return NULL;

	return yang_data_new_uint32(xpath, bs->discrs.remote_discr);
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/remote-state
 */
static struct yang_data *
bfdd_bfd_sessions_single_hop_stats_remote_state_get_elem(const char *xpath,
							 const void *list_entry)
{
	const struct bfd_session *bs = list_entry;

	return yang_data_new_enum(xpath, bs->ses_state);
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/remote-diagnostic
 */
static struct yang_data *
bfdd_bfd_sessions_single_hop_stats_remote_diagnostic_get_elem(
	const char *xpath, const void *list_entry)
{
	const struct bfd_session *bs = list_entry;

	return yang_data_new_enum(xpath, bs->remote_diag);
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/remote-multiplier
 */
static struct yang_data *
bfdd_bfd_sessions_single_hop_stats_remote_multiplier_get_elem(
	const char *xpath, const void *list_entry)
{
	const struct bfd_session *bs = list_entry;

	return yang_data_new_int8(xpath, bs->remote_detect_mult);
}

/*
 * XPath:
 * /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/negotiated-transmission-interval
 */
static struct yang_data *
bfdd_bfd_sessions_single_hop_stats_negotiated_transmission_interval_get_elem(
	const char *xpath, const void *list_entry)
{
	const struct bfd_session *bs = list_entry;

	return yang_data_new_uint32(xpath, bs->remote_timers.desired_min_tx);
}

/*
 * XPath:
 * /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/negotiated-receive-interval
 */
static struct yang_data *
bfdd_bfd_sessions_single_hop_stats_negotiated_receive_interval_get_elem(
	const char *xpath, const void *list_entry)
{
	const struct bfd_session *bs = list_entry;

	return yang_data_new_uint32(xpath, bs->remote_timers.required_min_rx);
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/detection-mode
 */
static struct yang_data *
bfdd_bfd_sessions_single_hop_stats_detection_mode_get_elem(
	const char *xpath, const void *list_entry)
{
	const struct bfd_session *bs = list_entry;
	int detection_mode;

	/*
	 * Detection mode:
	 *   1. Async with echo
	 *   2. Async without echo
	 *   3. Demand with echo
	 *   4. Demand without echo
	 *
	 * TODO: support demand mode.
	 */
	if (BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_ECHO))
		detection_mode = 1;
	else
		detection_mode = 2;

	return yang_data_new_enum(xpath, detection_mode);
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/last-down-time
 */
static struct yang_data *
bfdd_bfd_sessions_single_hop_stats_last_down_time_get_elem(
	const char *xpath __attribute__((__unused__)),
	const void *list_entry __attribute__((__unused__)))
{
	/*
	 * TODO: implement me.
	 *
	 * No yang support for time elements yet.
	 */
	return NULL;
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/last-up-time
 */
static struct yang_data *
bfdd_bfd_sessions_single_hop_stats_last_up_time_get_elem(
	const char *xpath __attribute__((__unused__)),
	const void *list_entry __attribute__((__unused__)))
{
	/*
	 * TODO: implement me.
	 *
	 * No yang support for time elements yet.
	 */
	return NULL;
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/session-down-count
 */
static struct yang_data *
bfdd_bfd_sessions_single_hop_stats_session_down_count_get_elem(
	const char *xpath, const void *list_entry)
{
	const struct bfd_session *bs = list_entry;

	return yang_data_new_uint64(xpath, bs->stats.session_down);
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/session-up-count
 */
static struct yang_data *
bfdd_bfd_sessions_single_hop_stats_session_up_count_get_elem(
	const char *xpath, const void *list_entry)
{
	const struct bfd_session *bs = list_entry;

	return yang_data_new_uint64(xpath, bs->stats.session_up);
}

/*
 * XPath:
 * /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/control-packet-input-count
 */
static struct yang_data *
bfdd_bfd_sessions_single_hop_stats_control_packet_input_count_get_elem(
	const char *xpath, const void *list_entry)
{
	const struct bfd_session *bs = list_entry;

	return yang_data_new_uint64(xpath, bs->stats.rx_ctrl_pkt);
}

/*
 * XPath:
 * /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/control-packet-output-count
 */
static struct yang_data *
bfdd_bfd_sessions_single_hop_stats_control_packet_output_count_get_elem(
	const char *xpath, const void *list_entry)
{
	const struct bfd_session *bs = list_entry;

	return yang_data_new_uint64(xpath, bs->stats.tx_ctrl_pkt);
}

/*
 * XPath:
 * /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/negotiated-echo-transmission-interval
 */
static struct yang_data *
bfdd_bfd_sessions_single_hop_stats_negotiated_echo_transmission_interval_get_elem(
	const char *xpath, const void *list_entry)
{
	const struct bfd_session *bs = list_entry;

	return yang_data_new_uint32(xpath, bs->remote_timers.required_min_echo);
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/echo-packet-input-count
 */
static struct yang_data *
bfdd_bfd_sessions_single_hop_stats_echo_packet_input_count_get_elem(
	const char *xpath, const void *list_entry)
{
	const struct bfd_session *bs = list_entry;

	return yang_data_new_uint64(xpath, bs->stats.rx_echo_pkt);
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/echo-packet-output-count
 */
static struct yang_data *
bfdd_bfd_sessions_single_hop_stats_echo_packet_output_count_get_elem(
	const char *xpath, const void *list_entry)
{
	const struct bfd_session *bs = list_entry;

	return yang_data_new_uint64(xpath, bs->stats.tx_echo_pkt);
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/multi-hop
 */
static int bfdd_bfd_sessions_multi_hop_create(enum nb_event event,
					      const struct lyd_node *dnode,
					      union nb_resource *resource)
{
	return bfd_session_create(event, dnode, resource, true);
}

static int bfdd_bfd_sessions_multi_hop_destroy(enum nb_event event,
					       const struct lyd_node *dnode)
{
	return bfd_session_destroy(event, dnode, true);
}

static const void *
bfdd_bfd_sessions_multi_hop_get_next(const void *parent_list_entry
				     __attribute__((__unused__)),
				     const void *list_entry)
{
	return bfd_session_next(list_entry, true);
}

static int bfdd_bfd_sessions_multi_hop_get_keys(const void *list_entry,
						struct yang_list_keys *keys)
{
	const struct bfd_session *bs = list_entry;
	char dstbuf[INET6_ADDRSTRLEN], srcbuf[INET6_ADDRSTRLEN];

	inet_ntop(bs->key.family, &bs->key.peer, dstbuf, sizeof(dstbuf));
	inet_ntop(bs->key.family, &bs->key.local, srcbuf, sizeof(srcbuf));

	keys->num = 4;
	strlcpy(keys->key[0], srcbuf, sizeof(keys->key[0]));
	strlcpy(keys->key[1], dstbuf, sizeof(keys->key[1]));
	strlcpy(keys->key[2], bs->key.ifname, sizeof(keys->key[2]));
	strlcpy(keys->key[3], bs->key.vrfname, sizeof(keys->key[3]));

	return NB_OK;
}

static const void *
bfdd_bfd_sessions_multi_hop_lookup_entry(const void *parent_list_entry
					 __attribute__((__unused__)),
					 const struct yang_list_keys *keys)
{
	const char *source_addr = keys->key[0];
	const char *dest_addr = keys->key[1];
	const char *ifname = keys->key[2];
	const char *vrf = keys->key[3];
	struct sockaddr_any psa, lsa;
	struct bfd_key bk;

	strtosa(dest_addr, &psa);
	strtosa(source_addr, &lsa);
	gen_bfd_key(&bk, &psa, &lsa, true, ifname, vrf);

	return bfd_key_lookup(bk);
}

/* clang-format off */
const struct frr_yang_module_info frr_bfdd_info = {
	.name = "frr-bfdd",
	.nodes = {
		{
			.xpath = "/frr-bfdd:bfdd/bfd",
			.cbs = {
				.create = bfdd_bfd_create,
				.destroy = bfdd_bfd_destroy,
				.cli_show = bfd_cli_show_header,
				.cli_show_end = bfd_cli_show_header_end,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop",
			.cbs = {
				.create = bfdd_bfd_sessions_single_hop_create,
				.destroy = bfdd_bfd_sessions_single_hop_destroy,
				.get_next = bfdd_bfd_sessions_single_hop_get_next,
				.get_keys = bfdd_bfd_sessions_single_hop_get_keys,
				.lookup_entry = bfdd_bfd_sessions_single_hop_lookup_entry,
				.cli_show = bfd_cli_show_single_hop_peer,
				.cli_show_end = bfd_cli_show_peer_end,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/source-addr",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_source_addr_modify,
				.destroy = bfdd_bfd_sessions_single_hop_source_addr_destroy,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/detection-multiplier",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_detection_multiplier_modify,
				.cli_show = bfd_cli_show_mult,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/desired-transmission-interval",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_desired_transmission_interval_modify,
				.cli_show = bfd_cli_show_tx,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/required-receive-interval",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_required_receive_interval_modify,
				.cli_show = bfd_cli_show_rx,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/administrative-down",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_administrative_down_modify,
				.cli_show = bfd_cli_show_shutdown,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/echo-mode",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_echo_mode_modify,
				.cli_show = bfd_cli_show_echo,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/desired-echo-transmission-interval",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_desired_echo_transmission_interval_modify,
				.cli_show = bfd_cli_show_echo_interval,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/local-discriminator",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_local_discriminator_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/local-state",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_local_state_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/local-diagnostic",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_local_diagnostic_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/local-multiplier",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_local_multiplier_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/remote-discriminator",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_remote_discriminator_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/remote-state",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_remote_state_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/remote-diagnostic",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_remote_diagnostic_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/remote-multiplier",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_remote_multiplier_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/negotiated-transmission-interval",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_negotiated_transmission_interval_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/negotiated-receive-interval",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_negotiated_receive_interval_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/detection-mode",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_detection_mode_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/last-down-time",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_last_down_time_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/last-up-time",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_last_up_time_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/session-down-count",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_session_down_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/session-up-count",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_session_up_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/control-packet-input-count",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_control_packet_input_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/control-packet-output-count",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_control_packet_output_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/negotiated-echo-transmission-interval",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_negotiated_echo_transmission_interval_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/echo-packet-input-count",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_echo_packet_input_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/echo-packet-output-count",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_echo_packet_output_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop",
			.cbs = {
				.create = bfdd_bfd_sessions_multi_hop_create,
				.destroy = bfdd_bfd_sessions_multi_hop_destroy,
				.get_next = bfdd_bfd_sessions_multi_hop_get_next,
				.get_keys = bfdd_bfd_sessions_multi_hop_get_keys,
				.lookup_entry = bfdd_bfd_sessions_multi_hop_lookup_entry,
				.cli_show = bfd_cli_show_multi_hop_peer,
				.cli_show_end = bfd_cli_show_peer_end,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/detection-multiplier",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_detection_multiplier_modify,
				.cli_show = bfd_cli_show_mult,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/desired-transmission-interval",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_desired_transmission_interval_modify,
				.cli_show = bfd_cli_show_tx,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/required-receive-interval",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_required_receive_interval_modify,
				.cli_show = bfd_cli_show_rx,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/administrative-down",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_administrative_down_modify,
				.cli_show = bfd_cli_show_shutdown,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/local-discriminator",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_local_discriminator_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/local-state",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_local_state_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/local-diagnostic",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_local_diagnostic_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/local-multiplier",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_local_multiplier_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/remote-discriminator",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_remote_discriminator_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/remote-state",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_remote_state_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/remote-diagnostic",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_remote_diagnostic_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/remote-multiplier",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_remote_multiplier_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/negotiated-transmission-interval",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_negotiated_transmission_interval_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/negotiated-receive-interval",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_negotiated_receive_interval_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/detection-mode",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_detection_mode_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/last-down-time",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_last_down_time_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/last-up-time",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_last_up_time_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/session-down-count",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_session_down_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/session-up-count",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_session_up_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/control-packet-input-count",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_control_packet_input_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/control-packet-output-count",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_control_packet_output_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/negotiated-echo-transmission-interval",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_negotiated_echo_transmission_interval_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/echo-packet-input-count",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_echo_packet_input_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/echo-packet-output-count",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_echo_packet_output_count_get_elem,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
