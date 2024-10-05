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
 * Helpers.
 */
static void bfd_session_get_key(bool mhop, const struct lyd_node *dnode,
				struct bfd_key *bk)
{
	const char *ifname = NULL, *vrfname = NULL;
	struct sockaddr_any psa, lsa;

	/* Required destination parameter. */
	strtosa(yang_dnode_get_string(dnode, "dest-addr"), &psa);

	/* Get optional source address. */
	memset(&lsa, 0, sizeof(lsa));
	if (yang_dnode_exists(dnode, "source-addr"))
		strtosa(yang_dnode_get_string(dnode, "source-addr"), &lsa);

	vrfname = yang_dnode_get_string(dnode, "vrf");

	if (!mhop) {
		ifname = yang_dnode_get_string(dnode, "interface");
		if (strcmp(ifname, "*") == 0)
			ifname = NULL;
	}

	/* Generate the corresponding key. */
	gen_bfd_key(bk, &psa, &lsa, mhop, ifname, vrfname);
}

struct session_iter {
	int count;
	bool wildcard;
};

static int session_iter_cb(const struct lyd_node *dnode, void *arg)
{
	struct session_iter *iter = arg;
	const char *ifname;

	ifname = yang_dnode_get_string(dnode, "interface");

	if (strmatch(ifname, "*"))
		iter->wildcard = true;

	iter->count++;

	return YANG_ITER_CONTINUE;
}

static int bfd_session_create(struct nb_cb_create_args *args, bool mhop)
{
	const struct lyd_node *sess_dnode;
	struct session_iter iter;
	struct bfd_session *bs;
	const char *dest;
	const char *ifname;
	const char *vrfname;
	struct bfd_key bk;
	struct prefix p;

	switch (args->event) {
	case NB_EV_VALIDATE:
		yang_dnode_get_prefix(&p, args->dnode, "dest-addr");

		if (mhop) {
			/*
			 * Do not allow IPv6 link-local address for multihop.
			 */
			if (p.family == AF_INET6
			    && IN6_IS_ADDR_LINKLOCAL(&p.u.prefix6)) {
				snprintf(
					args->errmsg, args->errmsg_len,
					"Cannot use link-local address for multihop sessions");
				return NB_ERR_VALIDATION;
			}
			return NB_OK;
		}

		/*
		 * When `dest-addr` is IPv6 and link-local we must
		 * require interface name, otherwise we can't figure
		 * which interface to use to send the packets.
		 */
		ifname = yang_dnode_get_string(args->dnode, "interface");

		if (p.family == AF_INET6 && IN6_IS_ADDR_LINKLOCAL(&p.u.prefix6)
		    && strcmp(ifname, "*") == 0) {
			snprintf(
				args->errmsg, args->errmsg_len,
				"When using link-local you must specify an interface");
			return NB_ERR_VALIDATION;
		}

		iter.count = 0;
		iter.wildcard = false;

		sess_dnode = yang_dnode_get_parent(args->dnode, "sessions");

		dest = yang_dnode_get_string(args->dnode, "dest-addr");
		vrfname = yang_dnode_get_string(args->dnode, "vrf");

		yang_dnode_iterate(session_iter_cb, &iter, sess_dnode,
				   "./single-hop[dest-addr='%s'][vrf='%s']",
				   dest, vrfname);

		if (iter.wildcard && iter.count > 1) {
			snprintf(
				args->errmsg, args->errmsg_len,
				"It is not allowed to configure the same peer with and without ifname");
			return NB_ERR_VALIDATION;
		}
		break;

	case NB_EV_PREPARE:
		bfd_session_get_key(mhop, args->dnode, &bk);
		bs = bfd_key_lookup(bk);

		/* This session was already configured by another daemon. */
		if (bs != NULL) {
			/* Now it is configured also by CLI. */
			SET_FLAG(bs->flags, BFD_SESS_FLAG_CONFIG);
			bs->refcount++;

			args->resource->ptr = bs;
			break;
		}

		bs = bfd_session_new();

		/* Fill the session key. */
		bfd_session_get_key(mhop, args->dnode, &bs->key);

		/* Set configuration flags. */
		bs->refcount = 1;
		SET_FLAG(bs->flags, BFD_SESS_FLAG_CONFIG);
		if (mhop)
			SET_FLAG(bs->flags, BFD_SESS_FLAG_MH);
		if (bs->key.family == AF_INET6)
			SET_FLAG(bs->flags, BFD_SESS_FLAG_IPV6);

		args->resource->ptr = bs;
		break;

	case NB_EV_APPLY:
		bs = args->resource->ptr;

		/* Only attempt to registrate if freshly allocated. */
		if (bs->discrs.my_discr == 0 && bs_registrate(bs) == NULL)
			return NB_ERR_RESOURCE;

		nb_running_set_entry(args->dnode, bs);
		break;

	case NB_EV_ABORT:
		bs = args->resource->ptr;
		if (bs->refcount <= 1)
			bfd_session_free(bs);
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
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/*
	 * Set any non-NULL value to be able to call
	 * nb_running_unset_entry in bfdd_bfd_destroy.
	 */
	nb_running_set_entry(args->dnode, (void *)0x1);

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
		/*
		 * We need to call this to unset pointers from
		 * the child nodes - sessions and profiles.
		 */
		nb_running_unset_entry(args->dnode);

		bfd_sessions_remove_manual();
		bfd_profiles_remove();
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

	name = yang_dnode_get_string(args->dnode, "name");
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

	switch (args->event) {
	case NB_EV_VALIDATE:
		break;

	case NB_EV_PREPARE:
		/* NOTHING */
		break;

	case NB_EV_APPLY:
		bp = nb_running_get_entry(args->dnode, NULL, true);
		bp->min_tx = yang_dnode_get_uint32(args->dnode, NULL);
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

	switch (args->event) {
	case NB_EV_VALIDATE:
		break;

	case NB_EV_PREPARE:
		/* NOTHING */
		break;

	case NB_EV_APPLY:
		bp = nb_running_get_entry(args->dnode, NULL, true);
		bp->min_rx = yang_dnode_get_uint32(args->dnode, NULL);
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

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bp = nb_running_get_entry(args->dnode, NULL, true);
	bp->admin_shutdown = yang_dnode_get_bool(args->dnode, NULL);
	bfd_profile_update(bp);

	return NB_OK;
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/profile/passive-mode
 */
int bfdd_bfd_profile_passive_mode_modify(struct nb_cb_modify_args *args)
{
	struct bfd_profile *bp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bp = nb_running_get_entry(args->dnode, NULL, true);
	bp->passive = yang_dnode_get_bool(args->dnode, NULL);
	bfd_profile_update(bp);

	return NB_OK;
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/profile/minimum-ttl
 */
int bfdd_bfd_profile_minimum_ttl_modify(struct nb_cb_modify_args *args)
{
	struct bfd_profile *bp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bp = nb_running_get_entry(args->dnode, NULL, true);
	bp->minimum_ttl = yang_dnode_get_uint8(args->dnode, NULL);
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
 * XPath: /frr-bfdd:bfdd/bfd/profile/desired-echo-transmission-interval
 */
int bfdd_bfd_profile_desired_echo_transmission_interval_modify(
	struct nb_cb_modify_args *args)
{
	struct bfd_profile *bp;

	switch (args->event) {
	case NB_EV_VALIDATE:
		break;

	case NB_EV_PREPARE:
		/* NOTHING */
		break;

	case NB_EV_APPLY:
		bp = nb_running_get_entry(args->dnode, NULL, true);
		bp->min_echo_tx = yang_dnode_get_uint32(args->dnode, NULL);
		bfd_profile_update(bp);
		break;

	case NB_EV_ABORT:
		/* NOTHING */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/profile/required-echo-receive-interval
 */
int bfdd_bfd_profile_required_echo_receive_interval_modify(
	struct nb_cb_modify_args *args)
{
	struct bfd_profile *bp;

	switch (args->event) {
	case NB_EV_VALIDATE:
		break;

	case NB_EV_PREPARE:
		/* NOTHING */
		break;

	case NB_EV_APPLY:
		bp = nb_running_get_entry(args->dnode, NULL, true);
		bp->min_echo_rx = yang_dnode_get_uint32(args->dnode, NULL);
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
	return bfd_session_create(args, false);
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
		bs->peer_profile.detection_multiplier = detection_multiplier;
		bfd_session_apply(bs);
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
	struct bfd_session *bs;

	switch (args->event) {
	case NB_EV_VALIDATE:
		break;

	case NB_EV_PREPARE:
		/* NOTHING */
		break;

	case NB_EV_APPLY:
		bs = nb_running_get_entry(args->dnode, NULL, true);
		bs->peer_profile.min_tx =
			yang_dnode_get_uint32(args->dnode, NULL);
		bfd_session_apply(bs);
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
	struct bfd_session *bs;

	switch (args->event) {
	case NB_EV_VALIDATE:
		break;

	case NB_EV_PREPARE:
		/* NOTHING */
		break;

	case NB_EV_APPLY:
		bs = nb_running_get_entry(args->dnode, NULL, true);
		bs->peer_profile.min_rx =
			yang_dnode_get_uint32(args->dnode, NULL);
		bfd_session_apply(bs);
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
	bfd_session_apply(bs);

	return NB_OK;
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/single-hop/passive-mode
 */
int bfdd_bfd_sessions_single_hop_passive_mode_modify(
	struct nb_cb_modify_args *args)
{
	struct bfd_session *bs;
	bool passive;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
		return NB_OK;

	case NB_EV_APPLY:
		break;

	case NB_EV_ABORT:
		return NB_OK;
	}

	passive = yang_dnode_get_bool(args->dnode, NULL);

	bs = nb_running_get_entry(args->dnode, NULL, true);
	bs->peer_profile.passive = passive;
	bfd_session_apply(bs);

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
	bfd_session_apply(bs);

	return NB_OK;
}

/*
 * XPath:
 * /frr-bfdd:bfdd/bfd/sessions/single-hop/desired-echo-transmission-interval
 */
int bfdd_bfd_sessions_single_hop_desired_echo_transmission_interval_modify(
	struct nb_cb_modify_args *args)
{
	struct bfd_session *bs;

	switch (args->event) {
	case NB_EV_VALIDATE:
		break;

	case NB_EV_PREPARE:
		/* NOTHING */
		break;

	case NB_EV_APPLY:
		bs = nb_running_get_entry(args->dnode, NULL, true);
		bs->peer_profile.min_echo_tx =
			yang_dnode_get_uint32(args->dnode, NULL);
		bfd_session_apply(bs);
		break;

	case NB_EV_ABORT:
		/* NOTHING */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-bfdd:bfdd/bfd/sessions/single-hop/required-echo-receive-interval
 */
int bfdd_bfd_sessions_single_hop_required_echo_receive_interval_modify(
	struct nb_cb_modify_args *args)
{
	struct bfd_session *bs;

	switch (args->event) {
	case NB_EV_VALIDATE:
		break;

	case NB_EV_PREPARE:
		/* NOTHING */
		break;

	case NB_EV_APPLY:
		bs = nb_running_get_entry(args->dnode, NULL, true);
		bs->peer_profile.min_echo_rx =
			yang_dnode_get_uint32(args->dnode, NULL);
		bfd_session_apply(bs);
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
	return bfd_session_create(args, true);
}

int bfdd_bfd_sessions_multi_hop_destroy(struct nb_cb_destroy_args *args)
{
	return bfd_session_destroy(args->event, args->dnode, true);
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/sessions/multi-hop/minimum-ttl
 */
int bfdd_bfd_sessions_multi_hop_minimum_ttl_modify(
	struct nb_cb_modify_args *args)
{
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
	bs->peer_profile.minimum_ttl = yang_dnode_get_uint8(args->dnode, NULL);
	bfd_session_apply(bs);

	return NB_OK;
}
