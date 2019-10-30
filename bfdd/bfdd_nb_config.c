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
				"%s: when using link-local you must specify "
				"an interface.",
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
int bfdd_bfd_create(enum nb_event event,
		    const struct lyd_node *dnode __attribute__((__unused__)),
		    union nb_resource *resource __attribute__((__unused__)))
{
	/* NOTHING */
	return NB_OK;
}

int bfdd_bfd_destroy(enum nb_event event, const struct lyd_node *dnode)
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
int bfdd_bfd_sessions_single_hop_create(enum nb_event event,
					const struct lyd_node *dnode,
					union nb_resource *resource)
{
	return bfd_session_create(event, dnode, resource, false);
}

int bfdd_bfd_sessions_single_hop_destroy(enum nb_event event,
					 const struct lyd_node *dnode)
{
	return bfd_session_destroy(event, dnode, false);
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/source-addr
 */
int bfdd_bfd_sessions_single_hop_source_addr_modify(enum nb_event event
						    __attribute__((__unused__)),
						    const struct lyd_node *dnode
						    __attribute__((__unused__)),
						    union nb_resource *resource
						    __attribute__((__unused__)))
{
	return NB_OK;
}

int bfdd_bfd_sessions_single_hop_source_addr_destroy(
	enum nb_event event __attribute__((__unused__)),
	const struct lyd_node *dnode __attribute__((__unused__)))
{
	return NB_OK;
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/detection-multiplier
 */
int bfdd_bfd_sessions_single_hop_detection_multiplier_modify(
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
int bfdd_bfd_sessions_single_hop_desired_transmission_interval_modify(
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
int bfdd_bfd_sessions_single_hop_required_receive_interval_modify(
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
int bfdd_bfd_sessions_single_hop_administrative_down_modify(
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
		control_notify(bs, bs->ses_state);

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
		control_notify(bs, bs->ses_state);

		ptm_bfd_snd(bs, 0);
	}

	return NB_OK;
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/echo-mode
 */
int bfdd_bfd_sessions_single_hop_echo_mode_modify(enum nb_event event,
						  const struct lyd_node *dnode,
						  union nb_resource *resource
						  __attribute__((__unused__)))
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
int bfdd_bfd_sessions_single_hop_desired_echo_transmission_interval_modify(
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
 * XPath: /frr-bfdd:bfdd/bfd/sessions/multi-hop
 */
int bfdd_bfd_sessions_multi_hop_create(enum nb_event event,
				       const struct lyd_node *dnode,
				       union nb_resource *resource)
{
	return bfd_session_create(event, dnode, resource, true);
}

int bfdd_bfd_sessions_multi_hop_destroy(enum nb_event event,
					const struct lyd_node *dnode)
{
	return bfd_session_destroy(event, dnode, true);
}
