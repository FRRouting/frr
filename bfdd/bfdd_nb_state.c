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
#include "bfdd_nb.h"

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop
 */
const void *bfdd_bfd_sessions_single_hop_get_next(const void *parent_list_entry
						  __attribute__((__unused__)),
						  const void *list_entry)
{
	return bfd_session_next(list_entry, false);
}

int bfdd_bfd_sessions_single_hop_get_keys(const void *list_entry,
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

const void *
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
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/local-discriminator
 */
struct yang_data *
bfdd_bfd_sessions_single_hop_stats_local_discriminator_get_elem(
	const char *xpath, const void *list_entry)
{
	const struct bfd_session *bs = list_entry;

	return yang_data_new_uint32(xpath, bs->discrs.my_discr);
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/local-state
 */
struct yang_data *
bfdd_bfd_sessions_single_hop_stats_local_state_get_elem(const char *xpath,
							const void *list_entry)
{
	const struct bfd_session *bs = list_entry;

	return yang_data_new_enum(xpath, bs->ses_state);
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/local-diagnostic
 */
struct yang_data *bfdd_bfd_sessions_single_hop_stats_local_diagnostic_get_elem(
	const char *xpath, const void *list_entry)
{
	const struct bfd_session *bs = list_entry;

	return yang_data_new_enum(xpath, bs->local_diag);
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/local-multiplier
 */
struct yang_data *bfdd_bfd_sessions_single_hop_stats_local_multiplier_get_elem(
	const char *xpath, const void *list_entry)
{
	const struct bfd_session *bs = list_entry;

	return yang_data_new_int8(xpath, bs->detect_mult);
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/remote-discriminator
 */
struct yang_data *
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
struct yang_data *
bfdd_bfd_sessions_single_hop_stats_remote_state_get_elem(const char *xpath,
							 const void *list_entry)
{
	const struct bfd_session *bs = list_entry;

	return yang_data_new_enum(xpath, bs->ses_state);
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/remote-diagnostic
 */
struct yang_data *bfdd_bfd_sessions_single_hop_stats_remote_diagnostic_get_elem(
	const char *xpath, const void *list_entry)
{
	const struct bfd_session *bs = list_entry;

	return yang_data_new_enum(xpath, bs->remote_diag);
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/remote-multiplier
 */
struct yang_data *bfdd_bfd_sessions_single_hop_stats_remote_multiplier_get_elem(
	const char *xpath, const void *list_entry)
{
	const struct bfd_session *bs = list_entry;

	return yang_data_new_int8(xpath, bs->remote_detect_mult);
}

/*
 * XPath:
 * /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/negotiated-transmission-interval
 */
struct yang_data *
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
struct yang_data *
bfdd_bfd_sessions_single_hop_stats_negotiated_receive_interval_get_elem(
	const char *xpath, const void *list_entry)
{
	const struct bfd_session *bs = list_entry;

	return yang_data_new_uint32(xpath, bs->remote_timers.required_min_rx);
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/detection-mode
 */
struct yang_data *bfdd_bfd_sessions_single_hop_stats_detection_mode_get_elem(
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
struct yang_data *bfdd_bfd_sessions_single_hop_stats_last_down_time_get_elem(
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
struct yang_data *bfdd_bfd_sessions_single_hop_stats_last_up_time_get_elem(
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
struct yang_data *
bfdd_bfd_sessions_single_hop_stats_session_down_count_get_elem(
	const char *xpath, const void *list_entry)
{
	const struct bfd_session *bs = list_entry;

	return yang_data_new_uint64(xpath, bs->stats.session_down);
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/session-up-count
 */
struct yang_data *bfdd_bfd_sessions_single_hop_stats_session_up_count_get_elem(
	const char *xpath, const void *list_entry)
{
	const struct bfd_session *bs = list_entry;

	return yang_data_new_uint64(xpath, bs->stats.session_up);
}

/*
 * XPath:
 * /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/control-packet-input-count
 */
struct yang_data *
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
struct yang_data *
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
struct yang_data *
bfdd_bfd_sessions_single_hop_stats_negotiated_echo_transmission_interval_get_elem(
	const char *xpath, const void *list_entry)
{
	const struct bfd_session *bs = list_entry;

	return yang_data_new_uint32(xpath, bs->remote_timers.required_min_echo);
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/echo-packet-input-count
 */
struct yang_data *
bfdd_bfd_sessions_single_hop_stats_echo_packet_input_count_get_elem(
	const char *xpath, const void *list_entry)
{
	const struct bfd_session *bs = list_entry;

	return yang_data_new_uint64(xpath, bs->stats.rx_echo_pkt);
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/stats/echo-packet-output-count
 */
struct yang_data *
bfdd_bfd_sessions_single_hop_stats_echo_packet_output_count_get_elem(
	const char *xpath, const void *list_entry)
{
	const struct bfd_session *bs = list_entry;

	return yang_data_new_uint64(xpath, bs->stats.tx_echo_pkt);
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/multi-hop
 */
const void *bfdd_bfd_sessions_multi_hop_get_next(const void *parent_list_entry
						 __attribute__((__unused__)),
						 const void *list_entry)
{
	return bfd_session_next(list_entry, true);
}

int bfdd_bfd_sessions_multi_hop_get_keys(const void *list_entry,
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

const void *
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
