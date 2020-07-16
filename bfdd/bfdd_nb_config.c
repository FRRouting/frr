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
	struct prefix p;

	switch (event) {
	case NB_EV_VALIDATE:
		/*
		 * When `dest-addr` is IPv6 and link-local we must
		 * require interface name, otherwise we can't figure
		 * which interface to use to send the packets.
		 */
		yang_dnode_get_prefix(&p, dnode, "./dest-addr");

		/*
		 * To support old FRR versions we must allow empty
		 * interface to be specified, however that should
		 * change in the future.
		 */
		if (yang_dnode_exists(dnode, "./interface"))
			ifname = yang_dnode_get_string(dnode, "./interface");
		else
			ifname = "";

		if (p.family == AF_INET6 && IN6_IS_ADDR_LINKLOCAL(&p.u.prefix6)
		    && strlen(ifname) == 0) {
			zlog_warn(
				"%s: when using link-local you must specify an interface.",
				__func__);
			return NB_ERR_VALIDATION;
		}
		break;

	case NB_EV_PREPARE:
		bfd_session_get_key(mhop, dnode, &bk);
		bs = bfd_key_lookup(bk);

		/* This session was already configured by another daemon. */
		if (bs != NULL) {
			/* Now it is configured also by CLI. */
			SET_FLAG(bs->flags, BFD_SESS_FLAG_CONFIG);
			bs->refcount++;

			resource->ptr = bs;
			break;
		}

		bs = bfd_session_new();

		/* Fill the session key. */
		bfd_session_get_key(mhop, dnode, &bs->key);

		/* Set configuration flags. */
		bs->refcount = 1;
		SET_FLAG(bs->flags, BFD_SESS_FLAG_CONFIG);
		if (mhop)
			SET_FLAG(bs->flags, BFD_SESS_FLAG_MH);
		if (bs->key.family == AF_INET6)
			SET_FLAG(bs->flags, BFD_SESS_FLAG_IPV6);

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
		if (CHECK_FLAG(bs->flags, BFD_SESS_FLAG_CONFIG) == 0)
			break;

		UNSET_FLAG(bs->flags, BFD_SESS_FLAG_CONFIG);
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
int bfdd_bfd_create(struct nb_cb_create_args *args)
{
	/* NOTHING */
	return NB_OK;
}

int bfdd_bfd_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
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
 * XPath: /frr-bfdd:bfdd/bfd/profile
 */
int bfdd_bfd_profile_create(struct nb_cb_create_args *args)
{
	struct bfd_profile *bp;
	const char *name;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	name = yang_dnode_get_string(args->dnode, "./name");
	bp = bfd_profile_new(name);
	nb_running_set_entry(args->dnode, bp);

	return NB_OK;
}

int bfdd_bfd_profile_destroy(struct nb_cb_destroy_args *args)
{
	struct bfd_profile *bp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bp = nb_running_unset_entry(args->dnode);
	bfd_profile_free(bp);

	return NB_OK;
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/profile/detection-multiplier
 */
int bfdd_bfd_profile_detection_multiplier_modify(struct nb_cb_modify_args *args)
{
	struct bfd_profile *bp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bp = nb_running_get_entry(args->dnode, NULL, true);
	bp->detection_multiplier = yang_dnode_get_uint8(args->dnode, NULL);
	bfd_profile_update(bp);

	return NB_OK;
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/profile/desired-transmission-interval
 */
int bfdd_bfd_profile_desired_transmission_interval_modify(
	struct nb_cb_modify_args *args)
{
	struct bfd_profile *bp;
	uint32_t min_tx;

	switch (args->event) {
	case NB_EV_VALIDATE:
		min_tx = yang_dnode_get_uint32(args->dnode, NULL);
		if (min_tx < 10000 || min_tx > 60000000)
			return NB_ERR_VALIDATION;
		break;

	case NB_EV_PREPARE:
		/* NOTHING */
		break;

	case NB_EV_APPLY:
		min_tx = yang_dnode_get_uint32(args->dnode, NULL);
		bp = nb_running_get_entry(args->dnode, NULL, true);
		if (bp->min_tx == min_tx)
			return NB_OK;

		bp->min_tx = min_tx;
		bfd_profile_update(bp);
		break;

	case NB_EV_ABORT:
		/* NOTHING */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/profile/required-receive-interval
 */
int bfdd_bfd_profile_required_receive_interval_modify(
	struct nb_cb_modify_args *args)
{
	struct bfd_profile *bp;
	uint32_t min_rx;

	switch (args->event) {
	case NB_EV_VALIDATE:
		min_rx = yang_dnode_get_uint32(args->dnode, NULL);
		if (min_rx < 10000 || min_rx > 60000000)
			return NB_ERR_VALIDATION;
		break;

	case NB_EV_PREPARE:
		/* NOTHING */
		break;

	case NB_EV_APPLY:
		min_rx = yang_dnode_get_uint32(args->dnode, NULL);
		bp = nb_running_get_entry(args->dnode, NULL, true);
		if (bp->min_rx == min_rx)
			return NB_OK;

		bp->min_rx = min_rx;
		bfd_profile_update(bp);
		break;

	case NB_EV_ABORT:
		/* NOTHING */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/profile/administrative-down
 */
int bfdd_bfd_profile_administrative_down_modify(struct nb_cb_modify_args *args)
{
	struct bfd_profile *bp;
	bool shutdown;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	shutdown = yang_dnode_get_bool(args->dnode, NULL);
	bp = nb_running_get_entry(args->dnode, NULL, true);
	if (bp->admin_shutdown == shutdown)
		return NB_OK;

	bp->admin_shutdown = shutdown;
	bfd_profile_update(bp);

	return NB_OK;
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/profile/echo-mode
 */
int bfdd_bfd_profile_echo_mode_modify(struct nb_cb_modify_args *args)
{
	struct bfd_profile *bp;
	bool echo;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	echo = yang_dnode_get_bool(args->dnode, NULL);
	bp = nb_running_get_entry(args->dnode, NULL, true);
	if (bp->echo_mode == echo)
		return NB_OK;

	bp->echo_mode = echo;
	bfd_profile_update(bp);

	return NB_OK;
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/profile/desired-echo-echo-transmission-interval
 */
int bfdd_bfd_profile_desired_echo_transmission_interval_modify(
	struct nb_cb_modify_args *args)
{
	struct bfd_profile *bp;
	uint32_t min_rx;

	switch (args->event) {
	case NB_EV_VALIDATE:
		min_rx = yang_dnode_get_uint32(args->dnode, NULL);
		if (min_rx < 10000 || min_rx > 60000000)
			return NB_ERR_VALIDATION;
		break;

	case NB_EV_PREPARE:
		/* NOTHING */
		break;

	case NB_EV_APPLY:
		min_rx = yang_dnode_get_uint32(args->dnode, NULL);
		bp = nb_running_get_entry(args->dnode, NULL, true);
		if (bp->min_echo_rx == min_rx)
			return NB_OK;

		bp->min_echo_rx = min_rx;
		bfd_profile_update(bp);
		break;

	case NB_EV_ABORT:
		/* NOTHING */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop
 */
int bfdd_bfd_sessions_single_hop_create(struct nb_cb_create_args *args)
{
	return bfd_session_create(args->event, args->dnode, args->resource,
				  false);
}

int bfdd_bfd_sessions_single_hop_destroy(struct nb_cb_destroy_args *args)
{
	return bfd_session_destroy(args->event, args->dnode, false);
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/source-addr
 */
int bfdd_bfd_sessions_single_hop_source_addr_modify(
	struct nb_cb_modify_args *args)
{
	return NB_OK;
}

int bfdd_bfd_sessions_single_hop_source_addr_destroy(
	struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/profile
 */
int bfdd_bfd_sessions_single_hop_profile_modify(struct nb_cb_modify_args *args)
{
	struct bfd_session *bs;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bs = nb_running_get_entry(args->dnode, NULL, true);
	bfd_profile_apply(yang_dnode_get_string(args->dnode, NULL), bs);

	return NB_OK;
}

int bfdd_bfd_sessions_single_hop_profile_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bfd_session *bs;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bs = nb_running_get_entry(args->dnode, NULL, true);
	bfd_profile_remove(bs);

	return NB_OK;
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/detection-multiplier
 */
int bfdd_bfd_sessions_single_hop_detection_multiplier_modify(
	struct nb_cb_modify_args *args)
{
	uint8_t detection_multiplier = yang_dnode_get_uint8(args->dnode, NULL);
	struct bfd_session *bs;

	switch (args->event) {
	case NB_EV_VALIDATE:
		break;

	case NB_EV_PREPARE:
		/* NOTHING */
		break;

	case NB_EV_APPLY:
		bs = nb_running_get_entry(args->dnode, NULL, true);
		bs->detect_mult = detection_multiplier;
		bs->peer_profile.detection_multiplier = detection_multiplier;
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
int bfdd_bfd_sessions_single_hop_desired_transmission_interval_modify(
	struct nb_cb_modify_args *args)
{
	uint32_t tx_interval = yang_dnode_get_uint32(args->dnode, NULL);
	struct bfd_session *bs;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (tx_interval < 10000 || tx_interval > 60000000)
			return NB_ERR_VALIDATION;
		break;

	case NB_EV_PREPARE:
		/* NOTHING */
		break;

	case NB_EV_APPLY:
		bs = nb_running_get_entry(args->dnode, NULL, true);
		if (tx_interval == bs->timers.desired_min_tx)
			return NB_OK;

		bs->timers.desired_min_tx = tx_interval;
		bs->peer_profile.min_tx = tx_interval;
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
int bfdd_bfd_sessions_single_hop_required_receive_interval_modify(
	struct nb_cb_modify_args *args)
{
	uint32_t rx_interval = yang_dnode_get_uint32(args->dnode, NULL);
	struct bfd_session *bs;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (rx_interval < 10000 || rx_interval > 60000000)
			return NB_ERR_VALIDATION;
		break;

	case NB_EV_PREPARE:
		/* NOTHING */
		break;

	case NB_EV_APPLY:
		bs = nb_running_get_entry(args->dnode, NULL, true);
		if (rx_interval == bs->timers.required_min_rx)
			return NB_OK;

		bs->timers.required_min_rx = rx_interval;
		bs->peer_profile.min_rx = rx_interval;
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
int bfdd_bfd_sessions_single_hop_administrative_down_modify(
	struct nb_cb_modify_args *args)
{
	bool shutdown = yang_dnode_get_bool(args->dnode, NULL);
	struct bfd_session *bs;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
		return NB_OK;

	case NB_EV_APPLY:
		break;

	case NB_EV_ABORT:
		return NB_OK;
	}

	bs = nb_running_get_entry(args->dnode, NULL, true);
	bs->peer_profile.admin_shutdown = shutdown;
	bfd_set_shutdown(bs, shutdown);

	return NB_OK;
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/echo-mode
 */
int bfdd_bfd_sessions_single_hop_echo_mode_modify(
	struct nb_cb_modify_args *args)
{
	bool echo = yang_dnode_get_bool(args->dnode, NULL);
	struct bfd_session *bs;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
		return NB_OK;

	case NB_EV_APPLY:
		break;

	case NB_EV_ABORT:
		return NB_OK;
	}

	bs = nb_running_get_entry(args->dnode, NULL, true);
	bs->peer_profile.echo_mode = echo;
	bfd_set_echo(bs, echo);

	return NB_OK;
}

/*
 * XPath:
 * /frr-bfdd:bfdd/bfd/sessions/single-hop/desired-echo-transmission-interval
 */
int bfdd_bfd_sessions_single_hop_desired_echo_transmission_interval_modify(
	struct nb_cb_modify_args *args)
{
	uint32_t echo_interval = yang_dnode_get_uint32(args->dnode, NULL);
	struct bfd_session *bs;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (echo_interval < 10000 || echo_interval > 60000000)
			return NB_ERR_VALIDATION;
		break;

	case NB_EV_PREPARE:
		/* NOTHING */
		break;

	case NB_EV_APPLY:
		bs = nb_running_get_entry(args->dnode, NULL, true);
		if (echo_interval == bs->timers.required_min_echo)
			return NB_OK;

		bs->timers.required_min_echo = echo_interval;
		bs->peer_profile.min_echo_rx = echo_interval;
		break;

	case NB_EV_ABORT:
		/* NOTHING */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/multi-hop
 */
int bfdd_bfd_sessions_multi_hop_create(struct nb_cb_create_args *args)
{
	return bfd_session_create(args->event, args->dnode, args->resource,
				  true);
}

int bfdd_bfd_sessions_multi_hop_destroy(struct nb_cb_destroy_args *args)
{
	return bfd_session_destroy(args->event, args->dnode, true);
}
