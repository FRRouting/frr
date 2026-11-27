// SPDX-License-Identifier: GPL-2.0-or-later
/* zebra_mroute code
 * Copyright (C) 2016 Cumulus Networks, Inc.
 * Donald Sharp
 *
 * This file is part of Quagga
 */

#include <zebra.h>

#include "stream.h"
#include "prefix.h"
#include "vrf.h"
#include "rib.h"
#include "jhash.h"
#include "typesafe.h"

#include "zebra/zserv.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_mroute.h"
#include "zebra/zebra_router.h"
#include "zebra/rt.h"
#include "zebra/debug.h"

DEFINE_MTYPE_STATIC(ZEBRA, ZMROUTE, "Multicast route");

/*
 * Multicast routes installed by the clients: the data plane has no idea which
 * process installed them, so they are withdrawn here when their client goes
 * away (like the kernel does when the multicast routing socket is closed).
 */
PREDECL_HASH(zmroute_owned);

/** Multicast route installed by a client. */
struct zmroute_entry {
	/** Installed routes hash entry. */
	struct zmroute_owned_item item;
	/** Client that installed it. */
	struct zserv *client;
	/** Last installation of the route (`DPLANE_OP_MROUTE_INSTALL`). */
	struct mroute_args args;
};

static int zmroute_entry_cmp(const struct zmroute_entry *a, const struct zmroute_entry *b)
{
	int rv;

	if (a->args.vrf_id != b->args.vrf_id)
		return a->args.vrf_id < b->args.vrf_id ? -1 : 1;

	rv = ipaddr_cmp(&a->args.source, &b->args.source);
	if (rv)
		return rv;

	return ipaddr_cmp(&a->args.group, &b->args.group);
}

static uint32_t zmroute_entry_hash(const struct zmroute_entry *entry)
{
	return jhash_3words(ipaddr_hash(&entry->args.source), ipaddr_hash(&entry->args.group),
			    entry->args.vrf_id, 0x5a6d7274);
}

DECLARE_HASH(zmroute_owned, struct zmroute_entry, item, zmroute_entry_cmp, zmroute_entry_hash);

/** Multicast routes installed by the clients. */
static struct zmroute_owned_head zmroute_owned_head;

void zebra_ipmr_route_stats(ZAPI_HANDLER_ARGS)
{
	struct mcast_route_data mroute;
	struct stream *s;
	int suc = -1;

	memset(&mroute, 0, sizeof(mroute));
	STREAM_GETL(msg, mroute.family);

	switch (mroute.family) {
	case AF_INET:
		SET_IPADDR_V4(&mroute.src);
		SET_IPADDR_V4(&mroute.grp);
		STREAM_GET(&mroute.src.ipaddr_v4, msg,
			   sizeof(mroute.src.ipaddr_v4));
		STREAM_GET(&mroute.grp.ipaddr_v4, msg,
			   sizeof(mroute.grp.ipaddr_v4));
		break;
	case AF_INET6:
		SET_IPADDR_V6(&mroute.src);
		SET_IPADDR_V6(&mroute.grp);
		STREAM_GET(&mroute.src.ipaddr_v6, msg,
			   sizeof(mroute.src.ipaddr_v6));
		STREAM_GET(&mroute.grp.ipaddr_v6, msg,
			   sizeof(mroute.grp.ipaddr_v6));
		break;
	default:
		zlog_warn("%s: Invalid address family received while parsing",
			  __func__);
		return;
	}

	STREAM_GETL(msg, mroute.ifindex);

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("Asking for (%pIA,%pIA)[%s(%u)] mroute information",
			   &mroute.src, &mroute.grp, zvrf->vrf->name,
			   zvrf->vrf->vrf_id);

	suc = kernel_get_ipmr_sg_stats(zvrf, &mroute);

stream_failure:
	s = stream_new(ZEBRA_SMALL_PACKET_SIZE);

	stream_reset(s);

	zclient_create_header(s, ZEBRA_IPMR_ROUTE_STATS, zvrf_id(zvrf));

	if (mroute.family == AF_INET) {
		stream_write(s, &mroute.src.ipaddr_v4,
			     sizeof(mroute.src.ipaddr_v4));
		stream_write(s, &mroute.grp.ipaddr_v4,
			     sizeof(mroute.grp.ipaddr_v4));
	} else {
		stream_write(s, &mroute.src.ipaddr_v6,
			     sizeof(mroute.src.ipaddr_v6));
		stream_write(s, &mroute.grp.ipaddr_v6,
			     sizeof(mroute.grp.ipaddr_v6));
	}

	stream_put(s, &mroute.lastused, sizeof(mroute.lastused));
	stream_putl(s, (uint32_t)suc);

	stream_putw_at(s, 0, stream_get_endp(s));
	zserv_send_message(client, s);
}

void zmroute_sync(vrf_id_t vrf_id)
{
	struct zserv *client;
	struct stream *stream;

	/* Create message. */
	stream = stream_new(ZEBRA_MAX_PACKET_SIZ);
	zclient_create_header(stream, ZEBRA_PIM_FPM_SYNC, vrf_id);
	stream_putw_at(stream, 0, (uint16_t)stream_get_endp(stream));

	/* Send message to all running PIM daemons. */
	frr_each (zserv_client_list, &zrouter.client_list, client) {
		if (client->proto != ZEBRA_ROUTE_PIM)
			continue;

		zserv_send_message(client, stream_dup(stream));
	}

	stream_free(stream);
}

struct mroute_oif_arg *mroute_oif_arg_new(struct mroute_oif_list *oif_list)
{
	struct mroute_oif_arg *oif;

	oif = XCALLOC(MTYPE_TMP, sizeof(*oif));
	SLIST_INSERT_HEAD(oif_list, oif, entry);

	return oif;
}

void mroute_oif_arg_free(struct mroute_oif_list *oif_list, struct mroute_oif_arg **oif)
{
	if (*oif == NULL)
		return;

	SLIST_REMOVE(oif_list, (*oif), mroute_oif_arg, entry);
	XFREE(MTYPE_TMP, (*oif));
}

void mroute_oif_list_free_all(struct mroute_oif_list *oif_list)
{
	while (!SLIST_EMPTY(oif_list)) {
		struct mroute_oif_arg *oif = SLIST_FIRST(oif_list);

		mroute_oif_arg_free(oif_list, &oif);
	}
}

static void zmroute_entry_free(struct zmroute_entry *entry)
{
	mroute_oif_list_free_all(&entry->args.oif_list);
	XFREE(MTYPE_ZMROUTE, entry);
}

/** Remembers which client installed the route (or forgets the deleted one). */
static void zmroute_track(struct zserv *client, const struct mroute_args *args)
{
	struct zmroute_entry lookup = { .args = *args };
	struct mroute_oif_arg *oif;
	struct zmroute_entry *entry;

	entry = zmroute_owned_find(&zmroute_owned_head, &lookup);
	if (args->mroute_op == DPLANE_OP_MROUTE_DELETE) {
		if (entry) {
			zmroute_owned_del(&zmroute_owned_head, entry);
			zmroute_entry_free(entry);
		}
		return;
	}

	if (entry)
		mroute_oif_list_free_all(&entry->args.oif_list);
	else {
		entry = XCALLOC(MTYPE_ZMROUTE, sizeof(*entry));
		entry->args = *args;
		zmroute_owned_add(&zmroute_owned_head, entry);
	}

	/* Replace the previous installation (keeping the hash key). */
	entry->client = client;
	entry->args = *args;
	SLIST_INIT(&entry->args.oif_list);
	SLIST_FOREACH (oif, &args->oif_list, entry)
		mroute_oif_arg_new(&entry->args.oif_list)->index = oif->index;
}

/** Withdraws the multicast routes the closing client installed. */
static int zmroute_client_close(struct zserv *client)
{
	struct zmroute_entry *entry;

	frr_each_safe (zmroute_owned, &zmroute_owned_head, entry) {
		if (entry->client != client)
			continue;

		zmroute_owned_del(&zmroute_owned_head, entry);

		/* On shutdown the data plane loses the FPM connection instead. */
		if (!zebra_router_in_shutdown()) {
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug("%s: withdrawing (%pIA,%pIA) vrf %u of closed client %s",
					   __func__, &entry->args.source, &entry->args.group,
					   entry->args.vrf_id, zebra_route_string(client->proto));

			entry->args.mroute_op = DPLANE_OP_MROUTE_DELETE;
			dplane_mroute_enqueue(&entry->args);
		}

		zmroute_entry_free(entry);
	}

	return 0;
}

void zebra_mroute_init(void)
{
	zmroute_owned_init(&zmroute_owned_head);
	hook_register(zserv_client_close, zmroute_client_close);
}

void zebra_mroute_terminate(void)
{
	struct zmroute_entry *entry;

	hook_unregister(zserv_client_close, zmroute_client_close);
	while ((entry = zmroute_owned_pop(&zmroute_owned_head)))
		zmroute_entry_free(entry);
	zmroute_owned_fini(&zmroute_owned_head);
}

void zmroute_event(ZAPI_HANDLER_ARGS)
{
	size_t output_idx;
	uint16_t family;
	uint16_t type;
	struct ipaddr ipa = {};
	struct mroute_args args = {
		.vrf_id = hdr->vrf_id,
	};

	STREAM_GETW(msg, type);
	if (type == 0)
		args.mroute_op = DPLANE_OP_MROUTE_INSTALL;
	else
		args.mroute_op = DPLANE_OP_MROUTE_DELETE;

	STREAM_GETW(msg, family);
	if (family == AF_INET) {
		ipa.ipa_type = IPADDR_V4;
		STREAM_GET(&ipa.ipaddr_v4, msg, sizeof(ipa.ipaddr_v4));
		args.source = ipa;

		STREAM_GET(&ipa.ipaddr_v4, msg, sizeof(ipa.ipaddr_v4));
		args.group = ipa;
	} else if (family == AF_INET6) {
		ipa.ipa_type = IPADDR_V6;
		STREAM_GET(&ipa.ipaddr_v6, msg, sizeof(ipa.ipaddr_v6));
		args.source = ipa;

		STREAM_GET(&ipa.ipaddr_v6, msg, sizeof(ipa.ipaddr_v6));
		args.group = ipa;
	} else {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("%s: unsupported address family %u", __func__, family);
		return;
	}

	STREAM_GETL(msg, args.input);
	STREAM_GETL(msg, args.notif_idx);
	STREAM_GETW(msg, args.flags);
	STREAM_GETW(msg, args.output_amount);

	for (output_idx = 0; output_idx < args.output_amount; output_idx++) {
		struct mroute_oif_arg *oif = mroute_oif_arg_new(&args.oif_list);
		ifindex_t index;

		STREAM_GETL(msg, index);
		oif->index = index;
	}

	STREAM_GETL(msg, args.spt_threshold);

	if (family == AF_INET) {
		STREAM_GET(&ipa.ipaddr_v4, msg, sizeof(ipa.ipaddr_v4));
		args.local = ipa;
		STREAM_GET(&ipa.ipaddr_v4, msg, sizeof(ipa.ipaddr_v4));
		args.remote = ipa;
	} else {
		STREAM_GET(&ipa.ipaddr_v6, msg, sizeof(ipa.ipaddr_v6));
		args.local = ipa;
		STREAM_GET(&ipa.ipaddr_v6, msg, sizeof(ipa.ipaddr_v6));
		args.remote = ipa;
	}

	zmroute_track(client, &args);
	dplane_mroute_enqueue(&args);
	mroute_oif_list_free_all(&args.oif_list);
	return;

stream_failure:
	mroute_oif_list_free_all(&args.oif_list);
	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("%s: message parse failure", __func__);
}
