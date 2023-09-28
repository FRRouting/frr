// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra opaque message handler module
 * Copyright (c) 2020 Volta Networks, Inc.
 */


#include <zebra.h>
#include "lib/debug.h"
#include "lib/frr_pthread.h"
#include "lib/stream.h"
#include "zebra/debug.h"
#include "zebra/zserv.h"
#include "zebra/zebra_opaque.h"
#include "zebra/rib.h"

/* Mem type */
DEFINE_MTYPE_STATIC(ZEBRA, OPQ, "ZAPI Opaque Information");

/* Hash to hold message registration info from zapi clients */
PREDECL_HASH(opq_regh);

/* Registered client info */
struct opq_client_reg {
	int proto;
	int instance;
	uint32_t session_id;

	int flags;

	struct opq_client_reg *next;
	struct opq_client_reg *prev;
};

/* Registration is for receiving or for notifications */
#define OPQ_CLIENT_FLAG_RECV   0x01
#define OPQ_CLIENT_FLAG_NOTIFY 0x02

/* Opaque message registration info */
struct opq_msg_reg {
	struct opq_regh_item item;

	/* Message type */
	uint32_t type;

	struct opq_client_reg *clients;
};

/* Registration helper prototypes */
static uint32_t registration_hash(const struct opq_msg_reg *reg);
static int registration_compare(const struct opq_msg_reg *reg1,
				const struct opq_msg_reg *reg2);

DECLARE_HASH(opq_regh, struct opq_msg_reg, item, registration_compare,
	     registration_hash);

static struct opq_regh_head opq_reg_hash;

/*
 * Globals
 */
static struct zebra_opaque_globals {

	/* Sentinel for run or start of shutdown */
	_Atomic uint32_t run;

	/* Limit number of pending, unprocessed updates */
	_Atomic uint32_t max_queued_updates;

	/* Limit number of new messages dequeued at once, to pace an
	 * incoming burst.
	 */
	uint32_t msgs_per_cycle;

	/* Stats: counters of incoming messages, errors, and yields (when
	 * the limit has been reached.)
	 */
	_Atomic uint32_t msgs_in;
	_Atomic uint32_t msg_errors;
	_Atomic uint32_t yields;

	/* pthread */
	struct frr_pthread *pthread;

	/* Event-delivery context 'master' for the module */
	struct event_loop *master;

	/* Event/'thread' pointer for queued zapi messages */
	struct event *t_msgs;

	/* Input fifo queue to the module, and lock to protect it. */
	pthread_mutex_t mutex;
	struct stream_fifo in_fifo;

} zo_info;

/* Name string for debugs/logs */
static const char LOG_NAME[] = "Zebra Opaque";

/* Prototypes */

/* Main event loop, processing incoming message queue */
static void process_messages(struct event *event);
static int handle_opq_registration(const struct zmsghdr *hdr,
				   struct stream *msg);
static int handle_opq_unregistration(const struct zmsghdr *hdr,
				     struct stream *msg);
static int handle_opq_notif_req(const struct zmsghdr *hdr, struct stream *msg);
static int handle_opq_notif_unreg(const struct zapi_opaque_notif_info *info);
static int dispatch_opq_messages(struct stream_fifo *msg_fifo);
static struct opq_msg_reg *opq_reg_lookup(uint32_t type);
static bool opq_client_match(const struct opq_client_reg *client,
			     const struct zapi_opaque_reg_info *info);
static bool opq_client_notif_match(const struct opq_client_reg *client,
				   const struct zapi_opaque_notif_info *info);
static struct opq_msg_reg *opq_reg_alloc(uint32_t type);
static void opq_reg_free(struct opq_msg_reg **reg);
static struct opq_client_reg *opq_client_alloc(uint8_t proto, uint16_t instance,
					       uint32_t session_id);
static void opq_client_free(struct opq_client_reg **client);
static const char *opq_client2str(char *buf, size_t buflen,
				  const struct opq_client_reg *client);

/*
 * Initialize the module at startup
 */
void zebra_opaque_init(void)
{
	memset(&zo_info, 0, sizeof(zo_info));

	pthread_mutex_init(&zo_info.mutex, NULL);
	stream_fifo_init(&zo_info.in_fifo);

	zo_info.msgs_per_cycle = ZEBRA_OPAQUE_MSG_LIMIT;
}

/*
 * Start the module pthread. This step is run later than the
 * 'init' step, in case zebra has fork-ed.
 */
void zebra_opaque_start(void)
{
	struct frr_pthread_attr pattr = {
		.start = frr_pthread_attr_default.start,
		.stop = frr_pthread_attr_default.stop
	};

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("%s module starting", LOG_NAME);

	/* Start pthread */
	zo_info.pthread = frr_pthread_new(&pattr, "Zebra Opaque thread",
					  "zebra_opaque");

	/* Associate event 'master' */
	zo_info.master = zo_info.pthread->master;

	atomic_store_explicit(&zo_info.run, 1, memory_order_relaxed);

	/* Enqueue an initial event for the pthread */
	event_add_event(zo_info.master, process_messages, NULL, 0,
			&zo_info.t_msgs);

	/* And start the pthread */
	frr_pthread_run(zo_info.pthread, NULL);
}

/*
 * Module stop, halting the dedicated pthread; called from the main pthread.
 */
void zebra_opaque_stop(void)
{
	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("%s module stop", LOG_NAME);

	atomic_store_explicit(&zo_info.run, 0, memory_order_relaxed);

	frr_pthread_stop(zo_info.pthread, NULL);

	frr_pthread_destroy(zo_info.pthread);

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("%s module stop complete", LOG_NAME);
}

/*
 * Module final cleanup, called from the zebra main pthread.
 */
void zebra_opaque_finish(void)
{
	struct opq_msg_reg *reg;
	struct opq_client_reg *client;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("%s module shutdown", LOG_NAME);

	/* Clear out registration info */
	while ((reg = opq_regh_pop(&opq_reg_hash)) != NULL) {
		client = reg->clients;
		while (client) {
			reg->clients = client->next;
			opq_client_free(&client);
			client = reg->clients;
		}

		opq_reg_free(&reg);
	}

	opq_regh_fini(&opq_reg_hash);

	pthread_mutex_destroy(&zo_info.mutex);
	stream_fifo_deinit(&zo_info.in_fifo);
}

/*
 * Does this module handle (intercept) the specified zapi message type?
 */
bool zebra_opaque_handles_msgid(uint16_t id)
{
	bool ret = false;

	switch (id) {
	case ZEBRA_OPAQUE_MESSAGE:
	case ZEBRA_OPAQUE_REGISTER:
	case ZEBRA_OPAQUE_UNREGISTER:
	case ZEBRA_OPAQUE_NOTIFY:
		ret = true;
		break;
	default:
		break;
	}

	return ret;
}

/*
 * Enqueue a batch of messages for processing - this is the public api
 * used from the zapi processing threads.
 */
uint32_t zebra_opaque_enqueue_batch(struct stream_fifo *batch)
{
	uint32_t counter = 0;
	struct stream *msg;

	/* Dequeue messages from the incoming batch, and save them
	 * on the module fifo.
	 */
	frr_with_mutex (&zo_info.mutex) {
		msg = stream_fifo_pop(batch);
		while (msg) {
			stream_fifo_push(&zo_info.in_fifo, msg);
			counter++;
			msg = stream_fifo_pop(batch);
		}
	}

	/* Schedule module's pthread to process the batch */
	if (counter > 0) {
		if (IS_ZEBRA_DEBUG_RECV && IS_ZEBRA_DEBUG_DETAIL)
			zlog_debug("%s: received %u messages",
				   __func__, counter);
		event_add_event(zo_info.master, process_messages, NULL, 0,
				&zo_info.t_msgs);
	}

	return counter;
}

/*
 * Pthread event loop, process the incoming message queue.
 */
static void process_messages(struct event *event)
{
	struct stream_fifo fifo;
	struct stream *msg;
	uint32_t i;
	bool need_resched = false;

	stream_fifo_init(&fifo);

	/* Check for zebra shutdown */
	if (atomic_load_explicit(&zo_info.run, memory_order_relaxed) == 0)
		goto done;

	/*
	 * Dequeue some messages from the incoming queue, temporarily
	 * save them on the local fifo
	 */
	frr_with_mutex (&zo_info.mutex) {

		for (i = 0; i < zo_info.msgs_per_cycle; i++) {
			msg = stream_fifo_pop(&zo_info.in_fifo);
			if (msg == NULL)
				break;

			stream_fifo_push(&fifo, msg);
		}

		/*
		 * We may need to reschedule, if there are still
		 * queued messages
		 */
		if (stream_fifo_head(&zo_info.in_fifo) != NULL)
			need_resched = true;
	}

	/* Update stats */
	atomic_fetch_add_explicit(&zo_info.msgs_in, i, memory_order_relaxed);

	/* Check for zebra shutdown */
	if (atomic_load_explicit(&zo_info.run, memory_order_relaxed) == 0) {
		need_resched = false;
		goto done;
	}

	if (IS_ZEBRA_DEBUG_RECV && IS_ZEBRA_DEBUG_DETAIL)
		zlog_debug("%s: processing %u messages", __func__, i);

	/*
	 * Process the messages from the temporary fifo. We send the whole
	 * fifo so that we can take advantage of batching internally. Note
	 * that registration/deregistration messages are handled here also.
	 */
	dispatch_opq_messages(&fifo);

done:

	if (need_resched) {
		atomic_fetch_add_explicit(&zo_info.yields, 1,
					  memory_order_relaxed);
		event_add_event(zo_info.master, process_messages, NULL, 0,
				&zo_info.t_msgs);
	}

	/* This will also free any leftover messages, in the shutdown case */
	stream_fifo_deinit(&fifo);
}

/*
 * Helper to acquire/lock a client session and send the message in 's'.
 * Note that 's' is enqueued for an io pthread, so don't free it
 * or touch it if this returns 'true'.
 */
static bool opq_send_message(uint8_t proto, uint16_t instance,
			     uint32_t session_id, struct stream *s)
{
	bool ret = false;
	struct zserv *zclient;

	/*
	 * TODO -- this isn't ideal: we're going through an
	 * acquire/release cycle for each client for each
	 * message. Replace this with a batching version.
	 */
	zclient = zserv_acquire_client(proto, instance, session_id);
	if (zclient) {
		/*
		 * Sending a message actually means enqueuing
		 * it for a zapi io pthread to send - so we
		 * don't touch the message after this call.
		 */
		zserv_send_message(zclient, s);

		zserv_release_client(zclient);
		ret = true;
	}

	return ret;
}

/*
 * Process (dispatch) or drop opaque messages.
 */
static int dispatch_opq_messages(struct stream_fifo *msg_fifo)
{
	struct stream *msg, *dup;
	struct zmsghdr hdr;
	struct zapi_opaque_msg info;
	struct opq_msg_reg *reg;
	int ret;
	struct opq_client_reg *client;
	char buf[50];

	while ((msg = stream_fifo_pop(msg_fifo)) != NULL) {
		zapi_parse_header(msg, &hdr);
		hdr.length -= ZEBRA_HEADER_SIZE;

		/* Handle client registration messages */
		if (hdr.command == ZEBRA_OPAQUE_REGISTER) {
			handle_opq_registration(&hdr, msg);
			continue;
		} else if (hdr.command == ZEBRA_OPAQUE_UNREGISTER) {
			handle_opq_unregistration(&hdr, msg);
			continue;
		} else if (hdr.command == ZEBRA_OPAQUE_NOTIFY) {
			handle_opq_notif_req(&hdr, msg);
			continue;
		}

		/* We only process OPAQUE messages - drop anything else */
		if (hdr.command != ZEBRA_OPAQUE_MESSAGE)
			goto drop_it;

		/* Dispatch to any registered ZAPI client(s) */

		/* Extract subtype and flags */
		ret = zclient_opaque_decode(msg, &info);
		if (ret != 0)
			goto drop_it;

		/* Look up registered ZAPI client(s) */
		reg = opq_reg_lookup(info.type);
		if (reg == NULL) {
			if (IS_ZEBRA_DEBUG_RECV && IS_ZEBRA_DEBUG_DETAIL)
				zlog_debug("%s: no registrations for opaque type %u, flags %#x",
					   __func__, info.type, info.flags);
			goto drop_it;
		}

		/* Reset read pointer, since we'll be re-sending message */
		stream_set_getp(msg, 0);

		/* Send a copy of the message to all registered clients */
		for (client = reg->clients; client; client = client->next) {
			dup = NULL;

			if (CHECK_FLAG(info.flags, ZAPI_OPAQUE_FLAG_UNICAST)) {

				if (client->proto != info.dest_proto ||
				    client->instance != info.dest_instance ||
				    client->session_id != info.dest_session_id)
					continue;

				if (IS_ZEBRA_DEBUG_RECV &&
				    IS_ZEBRA_DEBUG_DETAIL)
					zlog_debug("%s: found matching unicast client %s",
						   __func__,
						   opq_client2str(buf,
								  sizeof(buf),
								  client));

			} else {
				/* Copy message if more clients */
				if (client->next)
					dup = stream_dup(msg);
			}

			if (IS_ZEBRA_DEBUG_SEND && IS_ZEBRA_DEBUG_DETAIL)
				zlog_debug("%s: sending %s to client %s",
					   __func__, (dup ? "dup" : "msg"),
					   opq_client2str(buf, sizeof(buf),
							  client));

			/*
			 * TODO -- this isn't ideal: we're going through an
			 * acquire/release cycle for each client for each
			 * message. Replace this with a batching version.
			 */
			if (opq_send_message(client->proto, client->instance,
					     client->session_id,
					     (dup ? dup : msg))) {
				/* Message is gone - don't touch it */
				if (dup)
					dup = NULL;
				else
					msg = NULL;
			} else {
				if (IS_ZEBRA_DEBUG_RECV &&
				    IS_ZEBRA_DEBUG_DETAIL)
					zlog_debug("%s: type %u: no zclient for %s",
						   __func__, info.type,
						   opq_client2str(buf,
								  sizeof(buf),
								  client));
				/* Registered but gone? */
				if (dup)
					stream_free(dup);
			}

			/* If unicast, we're done */
			if (CHECK_FLAG(info.flags, ZAPI_OPAQUE_FLAG_UNICAST))
				break;
		}

drop_it:

		if (msg)
			stream_free(msg);
	}

	return 0;
}

/* Enqueue registration client object */
static void opq_enqueue_client(struct opq_msg_reg *reg,
			       struct opq_client_reg *client)
{
	client->next = reg->clients;
	if (reg->clients)
		reg->clients->prev = client;
	reg->clients = client;
}

/* Dequeue registration client object */
static void opq_dequeue_client(struct opq_msg_reg *reg,
			       struct opq_client_reg *client)
{
	if (client->prev)
		client->prev->next = client->next;
	if (client->next)
		client->next->prev = client->prev;
	if (reg->clients == client)
		reg->clients = client->next;
}

/*
 * Send notification messages to any interested clients in 'reg',
 * about 'server'; the sense is 'registered' (or not).
 * The 'server' is not required for un-registrations.
 */
static void opq_send_notifications(const struct opq_msg_reg *reg,
				   const struct opq_client_reg *server,
				   bool registered)
{
	const struct opq_client_reg *client;
	struct stream *msg = NULL;

	/* If there are any notification clients, send them a message */
	for (client = reg->clients; client; client = client->next) {
		if (CHECK_FLAG(client->flags, OPQ_CLIENT_FLAG_NOTIFY)) {
			msg = stream_new(ZEBRA_SMALL_PACKET_SIZE);

			if (registered) {
				zclient_opaque_notif_encode(msg, reg->type,
							    registered,
							    server->proto,
							    server->instance,
							    server->session_id);
			} else {
				zclient_opaque_notif_encode(msg, reg->type,
							    registered, 0, 0, 0);
			}

			/* Locate zebra client and enqueue message to it */
			if (!opq_send_message(client->proto, client->instance,
					      client->session_id, msg)) {
				/* Error - need to free the message */
				stream_free(msg);
			}
		}
	}
}

/*
 * Process a register/unregister message
 */
static int handle_opq_registration(const struct zmsghdr *hdr,
				   struct stream *msg)
{
	int ret = 0;
	struct zapi_opaque_reg_info info;
	struct opq_client_reg *client;
	struct opq_msg_reg key, *reg;
	char buf[50];

	memset(&info, 0, sizeof(info));

	if (zapi_opaque_reg_decode(msg, &info) < 0) {
		ret = -1;
		goto done;
	}

	memset(&key, 0, sizeof(key));

	key.type = info.type;

	reg = opq_regh_find(&opq_reg_hash, &key);
	if (reg) {
		/* Look for dup client */
		for (client = reg->clients; client != NULL;
		     client = client->next) {
			if (opq_client_match(client, &info))
				break;
		}

		if (client) {
			/* Oops - duplicate registration? */
			if (IS_ZEBRA_DEBUG_RECV)
				zlog_debug("%s: duplicate opq reg for client %s",
					   __func__,
					   opq_client2str(buf, sizeof(buf),
							  client));
			goto done;
		}

		client = opq_client_alloc(info.proto, info.instance,
					  info.session_id);
		SET_FLAG(client->flags, OPQ_CLIENT_FLAG_RECV);

		if (IS_ZEBRA_DEBUG_RECV)
			zlog_debug("%s: client %s registers for %u",
				   __func__,
				   opq_client2str(buf, sizeof(buf), client),
				   info.type);

		/* Link client into registration */
		opq_enqueue_client(reg, client);

		/* Send notifications to any clients who want them */
		opq_send_notifications(reg, client, true);

	} else {
		/*
		 * No existing registrations - create one, add the
		 * client, and add registration to hash.
		 */
		reg = opq_reg_alloc(info.type);
		client = opq_client_alloc(info.proto, info.instance,
					  info.session_id);
		SET_FLAG(client->flags, OPQ_CLIENT_FLAG_RECV);

		if (IS_ZEBRA_DEBUG_RECV)
			zlog_debug("%s: client %s registers for new reg %u",
				   __func__,
				   opq_client2str(buf, sizeof(buf), client),
				   info.type);

		reg->clients = client;

		opq_regh_add(&opq_reg_hash, reg);
	}

done:

	stream_free(msg);
	return ret;
}

/*
 * Process a register/unregister message
 */
static int handle_opq_unregistration(const struct zmsghdr *hdr,
				     struct stream *msg)
{
	int ret = 0;
	struct zapi_opaque_reg_info info;
	struct opq_client_reg *client, *tclient;
	struct opq_msg_reg key, *reg;
	int scount;
	char buf[50];

	memset(&info, 0, sizeof(info));

	if (zapi_opaque_reg_decode(msg, &info) < 0) {
		ret = -1;
		goto done;
	}

	memset(&key, 0, sizeof(key));

	key.type = info.type;

	reg = opq_regh_find(&opq_reg_hash, &key);
	if (reg == NULL) {
		/* Weird: unregister for unknown message? */
		if (IS_ZEBRA_DEBUG_RECV)
			zlog_debug("%s: unknown client %s/%u/%u unregisters for unknown type %u",
				   __func__,
				   zebra_route_string(info.proto),
				   info.instance, info.session_id, info.type);
		goto done;
	}

	/* Look for client info, count servers and notif clients too */
	client = NULL;
	scount = 0;

	for (tclient = reg->clients; tclient != NULL; tclient = tclient->next) {
		if (opq_client_match(tclient, &info))
			client = tclient;

		if (CHECK_FLAG(tclient->flags, OPQ_CLIENT_FLAG_RECV))
			scount++;
	}

	if (client == NULL) {
		/* Oops - unregister for unknown client? */
		if (IS_ZEBRA_DEBUG_RECV)
			zlog_debug("%s: unknown client %s/%u/%u unregisters for %u",
				   __func__, zebra_route_string(info.proto),
				   info.instance, info.session_id, info.type);
		goto done;
	}

	if (IS_ZEBRA_DEBUG_RECV)
		zlog_debug("%s: client %s unregisters for %u",
			   __func__, opq_client2str(buf, sizeof(buf), client),
			   info.type);

	opq_dequeue_client(reg, client);
	opq_client_free(&client);
	scount--;

	/* Is registration empty now? */
	if (reg->clients == NULL) {

		opq_regh_del(&opq_reg_hash, reg);
		opq_reg_free(&reg);
	} else if (scount == 0) {
		/* Send notifications if no more servers for the message. */
		opq_send_notifications(reg, NULL, false);
	}

done:

	stream_free(msg);
	return ret;
}

/*
 * Handle requests about opaque notifications.
 */
static int handle_opq_notif_req(const struct zmsghdr *hdr, struct stream *msg)
{
	int ret;
	struct zapi_opaque_notif_info info = {};
	struct opq_client_reg *client;
	struct opq_msg_reg key, *reg;
	char buf[50];

	ret = zclient_opaque_notif_decode(msg, &info);
	if (ret < 0)
		goto done;

	/* Handle deregistration */
	if (!info.reg) {
		ret = handle_opq_notif_unreg(&info);
		goto done;
	}

	memset(&key, 0, sizeof(key));

	key.type = info.msg_type;

	reg = opq_regh_find(&opq_reg_hash, &key);
	if (reg) {
		/* Look for dup client */
		for (client = reg->clients; client != NULL;
		     client = client->next) {
			if (opq_client_notif_match(client, &info))
				break;
		}

		if (client) {
			/* Oops - duplicate ? */
			if (IS_ZEBRA_DEBUG_RECV)
				zlog_debug("%s: duplicate opq notif reg client %s",
					   __func__, opq_client2str(buf,
								    sizeof(buf),
								    client));
			goto done;
		}

		client = opq_client_alloc(info.proto, info.instance,
					  info.session_id);
		SET_FLAG(client->flags, OPQ_CLIENT_FLAG_NOTIFY);

		if (IS_ZEBRA_DEBUG_RECV)
			zlog_debug("%s: client %s registers for notif %u",
				   __func__,
				   opq_client2str(buf, sizeof(buf), client),
				   info.msg_type);

		/* Link client into registration */
		opq_enqueue_client(reg, client);

		/* Send notification if any registered servers */
		/* Look for a server */
		for (client = reg->clients; client != NULL;
		     client = client->next) {
			if (CHECK_FLAG(client->flags, OPQ_CLIENT_FLAG_RECV))
				break;
		}
		if (client)
			opq_send_notifications(reg, client, true);

	} else if (info.reg) {
		/*
		 * No existing registrations - create one, add the
		 * client, and add registration to hash.
		 */
		reg = opq_reg_alloc(info.msg_type);
		client = opq_client_alloc(info.proto, info.instance,
					  info.session_id);
		SET_FLAG(client->flags, OPQ_CLIENT_FLAG_NOTIFY);

		if (IS_ZEBRA_DEBUG_RECV)
			zlog_debug("%s: client %s registers for new notif %u",
				   __func__,
				   opq_client2str(buf, sizeof(buf), client),
				   info.msg_type);

		reg->clients = client;

		opq_regh_add(&opq_reg_hash, reg);
	}

done:
	stream_free(msg);
	return ret;
}

/*
 * Unregister notification
 */
static int handle_opq_notif_unreg(const struct zapi_opaque_notif_info *info)
{
	int ret = 0;
	struct opq_client_reg *client;
	struct opq_msg_reg key, *reg;
	char buf[50];

	memset(&key, 0, sizeof(key));

	key.type = info->msg_type;

	reg = opq_regh_find(&opq_reg_hash, &key);
	if (reg == NULL) {
		/* Weird: unregister for unknown message? */
		if (IS_ZEBRA_DEBUG_RECV)
			zlog_debug("%s: unknown client %s/%u/%u unregisters notif for unknown type %u",
				   __func__, zebra_route_string(info->proto),
				   info->instance, info->session_id,
				   info->msg_type);
		goto done;
	}

	/* Look for client */
	for (client = reg->clients; client != NULL; client = client->next) {
		if (opq_client_notif_match(client, info))
			break;
	}

	if (client == NULL) {
		/* Oops - unregister for unknown client? */
		if (IS_ZEBRA_DEBUG_RECV)
			zlog_debug("%s: unknown client %s/%u/%u unregisters notif for %u",
				   __func__, zebra_route_string(info->proto),
				   info->instance, info->session_id,
				   info->msg_type);
		goto done;
	}

	if (IS_ZEBRA_DEBUG_RECV)
		zlog_debug("%s: client %s unregisters notif for %u", __func__,
			   opq_client2str(buf, sizeof(buf), client),
			   info->msg_type);

	/* Dequeue client object */
	opq_dequeue_client(reg, client);

	opq_client_free(&client);

	/* Is registration empty now? */
	if (reg->clients == NULL) {
		opq_regh_del(&opq_reg_hash, reg);
		opq_reg_free(&reg);
	}

done:

	return ret;
}

/* Compare utility for registered clients */
static bool opq_client_match(const struct opq_client_reg *client,
			     const struct zapi_opaque_reg_info *info)
{
	/* look for matching client, skip notifications */
	if (client->proto == info->proto && client->instance == info->instance &&
	    client->session_id == info->session_id &&
	    CHECK_FLAG(client->flags, OPQ_CLIENT_FLAG_RECV))
		return true;
	else
		return false;
}

/* Compare helper for clients registered for notifications */
static bool opq_client_notif_match(const struct opq_client_reg *client,
				   const struct zapi_opaque_notif_info *info)
{
	/* look for matching client, only for notifications */
	if (client->proto == info->proto && client->instance == info->instance &&
	    client->session_id == info->session_id &&
	    CHECK_FLAG(client->flags, OPQ_CLIENT_FLAG_NOTIFY))
		return true;
	else
		return false;
}

static struct opq_msg_reg *opq_reg_lookup(uint32_t type)
{
	struct opq_msg_reg key, *reg;

	memset(&key, 0, sizeof(key));

	key.type = type;

	reg = opq_regh_find(&opq_reg_hash, &key);

	return reg;
}

static struct opq_msg_reg *opq_reg_alloc(uint32_t type)
{
	struct opq_msg_reg *reg;

	reg = XCALLOC(MTYPE_OPQ, sizeof(struct opq_msg_reg));

	reg->type = type;
	INIT_HASH(&reg->item);

	return reg;
}

static void opq_reg_free(struct opq_msg_reg **reg)
{
	XFREE(MTYPE_OPQ, (*reg));
}

static struct opq_client_reg *opq_client_alloc(uint8_t proto, uint16_t instance,
					       uint32_t session_id)
{
	struct opq_client_reg *client;

	client = XCALLOC(MTYPE_OPQ, sizeof(struct opq_client_reg));

	client->proto = proto;
	client->instance = instance;
	client->session_id = session_id;

	return client;
}

static void opq_client_free(struct opq_client_reg **client)
{
	XFREE(MTYPE_OPQ, (*client));
}

static const char *opq_client2str(char *buf, size_t buflen,
				  const struct opq_client_reg *client)
{
	char sbuf[20];

	snprintf(buf, buflen, "%s/%u", zebra_route_string(client->proto),
		 client->instance);
	if (client->session_id > 0) {
		snprintf(sbuf, sizeof(sbuf), "/%u", client->session_id);
		strlcat(buf, sbuf, buflen);
	}

	return buf;
}

/* Hash function for clients registered for messages */
static uint32_t registration_hash(const struct opq_msg_reg *reg)
{
	return reg->type;
}

/* Comparison function for client registrations */
static int registration_compare(const struct opq_msg_reg *reg1,
				const struct opq_msg_reg *reg2)
{
	if (reg1->type == reg2->type)
		return 0;
	else
		return -1;
}
