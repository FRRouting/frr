// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BFD daemon northbound implementation.
 *
 * Copyright (C) 2019 Network Device Education Foundation, Inc. ("NetDEF")
 *                    Rafael Zalamena
 */

#include <zebra.h>

#include "lib/log.h"
#include "lib/northbound.h"

#include "bfd.h"
#include "bfdd_nb.h"

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop
 */
const void *
bfdd_bfd_sessions_single_hop_get_next(struct nb_cb_get_next_args *args)
{
	return bfd_session_next(args->list_entry, false);
}

int bfdd_bfd_sessions_single_hop_get_keys(struct nb_cb_get_keys_args *args)
{
	const struct bfd_session *bs = args->list_entry;
	char dstbuf[INET6_ADDRSTRLEN];

	inet_ntop(bs->key.family, &bs->key.peer, dstbuf, sizeof(dstbuf));

	args->keys->num = 3;
	strlcpy(args->keys->key[0], dstbuf, sizeof(args->keys->key[0]));
	strlcpy(args->keys->key[1], bs->key.ifname, sizeof(args->keys->key[1]));
	strlcpy(args->keys->key[2], bs->key.vrfname,
		sizeof(args->keys->key[2]));

	return NB_OK;
}

const void *
bfdd_bfd_sessions_single_hop_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	const char *dest_addr = args->keys->key[0];
	const char *ifname = args->keys->key[1];
	const char *vrf = args->keys->key[2];
	struct sockaddr_any psa, lsa;
	struct bfd_key bk;

	strtosa(dest_addr, &psa);
	memset(&lsa, 0, sizeof(lsa));
	gen_bfd_key(&bk, &psa, &lsa, false, ifname, vrf);

	return bfd_key_lookup(bk);
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/local-discriminator
 */
struct yang_data *
bfdd_bfd_sessions_single_hop_stats_local_discriminator_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct bfd_session *bs = args->list_entry;

	return yang_data_new_uint32(args->xpath, bs->discrs.my_discr);
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/local-state
 */
struct yang_data *bfdd_bfd_sessions_single_hop_stats_local_state_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct bfd_session *bs = args->list_entry;

	return yang_data_new_enum(args->xpath, bs->ses_state);
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/local-diagnostic
 */
struct yang_data *bfdd_bfd_sessions_single_hop_stats_local_diagnostic_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct bfd_session *bs = args->list_entry;

	return yang_data_new_enum(args->xpath, bs->local_diag);
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/local-multiplier
 */
struct yang_data *bfdd_bfd_sessions_single_hop_stats_local_multiplier_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct bfd_session *bs = args->list_entry;

	return yang_data_new_int8(args->xpath, bs->detect_mult);
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/remote-discriminator
 */
struct yang_data *
bfdd_bfd_sessions_single_hop_stats_remote_discriminator_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct bfd_session *bs = args->list_entry;

	if (bs->discrs.remote_discr == 0)
		return NULL;

	return yang_data_new_uint32(args->xpath, bs->discrs.remote_discr);
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/remote-state
 */
struct yang_data *bfdd_bfd_sessions_single_hop_stats_remote_state_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct bfd_session *bs = args->list_entry;

	return yang_data_new_enum(args->xpath, bs->ses_state);
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/remote-diagnostic
 */
struct yang_data *bfdd_bfd_sessions_single_hop_stats_remote_diagnostic_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct bfd_session *bs = args->list_entry;

	return yang_data_new_enum(args->xpath, bs->remote_diag);
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/remote-multiplier
 */
struct yang_data *bfdd_bfd_sessions_single_hop_stats_remote_multiplier_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct bfd_session *bs = args->list_entry;

	return yang_data_new_int8(args->xpath, bs->remote_detect_mult);
}

/*
 * XPath:
 * /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/negotiated-transmission-interval
 */
struct yang_data *
bfdd_bfd_sessions_single_hop_stats_negotiated_transmission_interval_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct bfd_session *bs = args->list_entry;

	return yang_data_new_uint32(args->xpath,
				    bs->remote_timers.desired_min_tx);
}

/*
 * XPath:
 * /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/negotiated-receive-interval
 */
struct yang_data *
bfdd_bfd_sessions_single_hop_stats_negotiated_receive_interval_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct bfd_session *bs = args->list_entry;

	return yang_data_new_uint32(args->xpath,
				    bs->remote_timers.required_min_rx);
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/detection-mode
 */
struct yang_data *bfdd_bfd_sessions_single_hop_stats_detection_mode_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct bfd_session *bs = args->list_entry;
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
	if (CHECK_FLAG(bs->flags, BFD_SESS_FLAG_ECHO))
		detection_mode = 1;
	else
		detection_mode = 2;

	return yang_data_new_enum(args->xpath, detection_mode);
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/last-down-time
 */
struct yang_data *bfdd_bfd_sessions_single_hop_stats_last_down_time_get_elem(
	struct nb_cb_get_elem_args *args)
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
struct yang_data *bfdd_bfd_sessions_single_hop_stats_last_up_time_get_elem(
	struct nb_cb_get_elem_args *args)
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
struct yang_data *
bfdd_bfd_sessions_single_hop_stats_session_down_count_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct bfd_session *bs = args->list_entry;

	return yang_data_new_uint64(args->xpath, bs->stats.session_down);
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/session-up-count
 */
struct yang_data *bfdd_bfd_sessions_single_hop_stats_session_up_count_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct bfd_session *bs = args->list_entry;

	return yang_data_new_uint64(args->xpath, bs->stats.session_up);
}

/*
 * XPath:
 * /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/control-packet-input-count
 */
struct yang_data *
bfdd_bfd_sessions_single_hop_stats_control_packet_input_count_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct bfd_session *bs = args->list_entry;

	return yang_data_new_uint64(args->xpath, bs->stats.rx_ctrl_pkt);
}

/*
 * XPath:
 * /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/control-packet-output-count
 */
struct yang_data *
bfdd_bfd_sessions_single_hop_stats_control_packet_output_count_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct bfd_session *bs = args->list_entry;

	return yang_data_new_uint64(args->xpath, bs->stats.tx_ctrl_pkt);
}

/*
 * XPath:
 * /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/negotiated-echo-transmission-interval
 */
struct yang_data *
bfdd_bfd_sessions_single_hop_stats_negotiated_echo_transmission_interval_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct bfd_session *bs = args->list_entry;

	return yang_data_new_uint32(args->xpath,
				    bs->remote_timers.required_min_echo);
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/echo-packet-input-count
 */
struct yang_data *
bfdd_bfd_sessions_single_hop_stats_echo_packet_input_count_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct bfd_session *bs = args->list_entry;

	return yang_data_new_uint64(args->xpath, bs->stats.rx_echo_pkt);
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/echo-packet-output-count
 */
struct yang_data *
bfdd_bfd_sessions_single_hop_stats_echo_packet_output_count_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct bfd_session *bs = args->list_entry;

	return yang_data_new_uint64(args->xpath, bs->stats.tx_echo_pkt);
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/multi-hop
 */
const void *
bfdd_bfd_sessions_multi_hop_get_next(struct nb_cb_get_next_args *args)
{
	return bfd_session_next(args->list_entry, true);
}

int bfdd_bfd_sessions_multi_hop_get_keys(struct nb_cb_get_keys_args *args)
{
	const struct bfd_session *bs = args->list_entry;
	char dstbuf[INET6_ADDRSTRLEN], srcbuf[INET6_ADDRSTRLEN];

	inet_ntop(bs->key.family, &bs->key.peer, dstbuf, sizeof(dstbuf));
	inet_ntop(bs->key.family, &bs->key.local, srcbuf, sizeof(srcbuf));

	args->keys->num = 4;
	strlcpy(args->keys->key[0], srcbuf, sizeof(args->keys->key[0]));
	strlcpy(args->keys->key[1], dstbuf, sizeof(args->keys->key[1]));
	strlcpy(args->keys->key[2], bs->key.vrfname,
		sizeof(args->keys->key[2]));

	return NB_OK;
}

const void *
bfdd_bfd_sessions_multi_hop_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	const char *source_addr = args->keys->key[0];
	const char *dest_addr = args->keys->key[1];
	const char *vrf = args->keys->key[2];
	struct sockaddr_any psa, lsa;
	struct bfd_key bk;

	strtosa(dest_addr, &psa);
	strtosa(source_addr, &lsa);
	gen_bfd_key(&bk, &psa, &lsa, true, NULL, vrf);

	return bfd_key_lookup(bk);
}
