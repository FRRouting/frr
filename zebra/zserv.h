// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra API server.
 * Portions:
 *   Copyright (C) 1997-1999  Kunihiro Ishiguro
 *   Copyright (C) 2015-2018  Cumulus Networks, Inc.
 *   et al.
 */

#ifndef _ZEBRA_ZSERV_H
#define _ZEBRA_ZSERV_H

/* clang-format off */
#include <stdint.h>           /* for uint32_t, uint8_t */
#include <time.h>             /* for time_t */

#include "lib/route_types.h"  /* for ZEBRA_ROUTE_MAX */
#include "lib/zebra.h"        /* for AFI_MAX */
#include "lib/vrf.h"          /* for vrf_bitmap_t */
#include "lib/zclient.h"      /* for redist_proto */
#include "lib/stream.h"       /* for stream, stream_fifo */
#include "frrevent.h"            /* for thread, thread_master */
#include "lib/linklist.h"     /* for list */
#include "lib/workqueue.h"    /* for work_queue */
#include "lib/hook.h"         /* for DECLARE_HOOK, DECLARE_KOOH */
/* clang-format on */

#ifdef __cplusplus
extern "C" {
#endif

struct zebra_vrf;

/* Default configuration filename. */
#define DEFAULT_CONFIG_FILE "zebra.conf"

#define ZEBRA_RMAP_DEFAULT_UPDATE_TIMER 5 /* disabled by default */


/* Stale route marker timer */
#define ZEBRA_DEFAULT_STALE_UPDATE_DELAY 1

/* Count of stale routes processed in timer context */
#define ZEBRA_MAX_STALE_ROUTE_COUNT 50000

/* Graceful Restart information */
struct client_gr_info {
	/* VRF for which GR enabled */
	vrf_id_t vrf_id;

	/* Stale time and GR cap */
	uint32_t stale_removal_time;
	enum zserv_client_capabilities capabilities;

	/* GR commands */
	bool do_delete;
	bool gr_enable;
	bool stale_client;

	/* Route sync and enable flags for AFI/SAFI */
	bool af_enabled[AFI_MAX];
	bool route_sync[AFI_MAX];

	/* Book keeping */
	void *stale_client_ptr;
	struct event *t_stale_removal;

	TAILQ_ENTRY(client_gr_info) gr_info;
};

/* Client structure. */
struct zserv {
	/* Client pthread */
	struct frr_pthread *pthread;

	/* Client file descriptor. */
	int sock;

	/* Attributes used to permit access to zapi clients from
	 * other pthreads: the client has a busy counter, and a
	 * 'closed' flag. These attributes are managed using a
	 * lock, via the acquire_client() and release_client() apis.
	 */
	int busy_count;
	bool is_closed;

	/* Input/output buffer to the client. */
	pthread_mutex_t ibuf_mtx;
	struct stream_fifo *ibuf_fifo;
	pthread_mutex_t obuf_mtx;
	struct stream_fifo *obuf_fifo;

	/* Private I/O buffers */
	struct stream *ibuf_work;
	struct stream *obuf_work;

	/* Buffer of data waiting to be written to client. */
	struct buffer *wb;

	/* Threads for read/write. */
	struct event *t_read;
	struct event *t_write;

	/* Event for message processing, for the main pthread */
	struct event *t_process;

	/* Event for the main pthread */
	struct event *t_cleanup;

	/* This client's redistribute flag. */
	struct redist_proto mi_redist[AFI_MAX][ZEBRA_ROUTE_MAX];
	vrf_bitmap_t redist[AFI_MAX][ZEBRA_ROUTE_MAX];

	/* Redistribute default route flag. */
	vrf_bitmap_t redist_default[AFI_MAX];

	/* Router-id information. */
	vrf_bitmap_t ridinfo[AFI_MAX];

	/* Router-id information. */
	vrf_bitmap_t neighinfo[AFI_MAX];

	bool notify_owner;

	/* Indicates if client is synchronous. */
	bool synchronous;

	/* client's protocol and session info */
	uint8_t proto;
	uint16_t instance;
	uint32_t session_id;

	/*
	 * Interested for MLAG Updates, and also stores the client
	 * interested message mask
	 */
	bool mlag_updates_interested;
	uint32_t mlag_reg_mask1;

	/* Statistics */
	uint32_t redist_v4_add_cnt;
	uint32_t redist_v4_del_cnt;
	uint32_t redist_v6_add_cnt;
	uint32_t redist_v6_del_cnt;
	uint32_t v4_route_add_cnt;
	uint32_t v4_route_upd8_cnt;
	uint32_t v4_route_del_cnt;
	uint32_t v6_route_add_cnt;
	uint32_t v6_route_del_cnt;
	uint32_t v6_route_upd8_cnt;
	uint32_t connected_rt_add_cnt;
	uint32_t connected_rt_del_cnt;
	uint32_t ifup_cnt;
	uint32_t ifdown_cnt;
	uint32_t ifadd_cnt;
	uint32_t ifdel_cnt;
	uint32_t if_bfd_cnt;
	uint32_t bfd_peer_add_cnt;
	uint32_t bfd_peer_upd8_cnt;
	uint32_t bfd_peer_del_cnt;
	uint32_t bfd_peer_replay_cnt;
	uint32_t vrfadd_cnt;
	uint32_t vrfdel_cnt;
	uint32_t if_vrfchg_cnt;
	uint32_t bfd_client_reg_cnt;
	uint32_t vniadd_cnt;
	uint32_t vnidel_cnt;
	uint32_t l3vniadd_cnt;
	uint32_t l3vnidel_cnt;
	uint32_t macipadd_cnt;
	uint32_t macipdel_cnt;
	uint32_t prefixadd_cnt;
	uint32_t prefixdel_cnt;
	uint32_t v4_nh_watch_add_cnt;
	uint32_t v4_nh_watch_rem_cnt;
	uint32_t v6_nh_watch_add_cnt;
	uint32_t v6_nh_watch_rem_cnt;
	uint32_t vxlan_sg_add_cnt;
	uint32_t vxlan_sg_del_cnt;
	uint32_t local_es_add_cnt;
	uint32_t local_es_del_cnt;
	uint32_t local_es_evi_add_cnt;
	uint32_t local_es_evi_del_cnt;
	uint32_t error_cnt;
	uint32_t nhg_add_cnt;
	uint32_t nhg_upd8_cnt;
	uint32_t nhg_del_cnt;

	time_t nh_reg_time;
	time_t nh_dereg_time;
	time_t nh_last_upd_time;

	/*
	 * Session information.
	 *
	 * These are not synchronous with respect to each other. For instance,
	 * last_read_cmd may contain a value that has been read in the future
	 * relative to last_read_time.
	 */

	pthread_mutex_t stats_mtx;
	/* BEGIN covered by stats_mtx */

	/* monotime of client creation */
	uint64_t connect_time;
	/* monotime of last message received */
	uint64_t last_read_time;
	/* monotime of last message sent */
	uint64_t last_write_time;
	/* command code of last message read */
	uint64_t last_read_cmd;
	/* command code of last message written */
	uint64_t last_write_cmd;

	/* END covered by stats_mtx */

	/*
	 * Number of instances configured with
	 * graceful restart
	 */
	uint32_t gr_instance_count;
	time_t restart_time;

	/*
	 * Graceful restart information for
	 * each instance
	 */
	TAILQ_HEAD(info_list, client_gr_info) gr_info_queue;
};

#define ZAPI_HANDLER_ARGS                                                      \
	struct zserv *client, struct zmsghdr *hdr, struct stream *msg,         \
		struct zebra_vrf *zvrf

/* Hooks for client connect / disconnect */
DECLARE_HOOK(zserv_client_connect, (struct zserv *client), (client));
DECLARE_KOOH(zserv_client_close, (struct zserv *client), (client));

#define DYNAMIC_CLIENT_GR_DISABLED(_client)                                    \
	((_client->proto <= ZEBRA_ROUTE_LOCAL) || !(_client->gr_instance_count))

/*
 * Initialize Zebra API server.
 *
 * Installs CLI commands and creates the client list.
 */
extern void zserv_init(void);

/*
 * Stop the Zebra API server.
 *
 * closes the socket
 */
extern void zserv_close(void);

/*
 * Start Zebra API server.
 *
 * Allocates resources, creates the server socket and begins listening on the
 * socket.
 *
 * path
 *    where to place the Unix domain socket
 */
extern void zserv_start(char *path);

/*
 * Send a message to a connected Zebra API client.
 *
 * client
 *    the client to send to
 *
 * msg
 *    the message to send
 */
extern int zserv_send_message(struct zserv *client, struct stream *msg);

/*
 * Send a batch of messages to a connected Zebra API client.
 *
 * client
 *    the client to send to
 *
 * fifo
 *    the list of messages to send
 */
extern int zserv_send_batch(struct zserv *client, struct stream_fifo *fifo);

/*
 * Retrieve a client by its protocol and instance number.
 *
 * proto
 *    protocol number
 *
 * instance
 *    instance number
 *
 * Returns:
 *    The Zebra API client.
 */
extern struct zserv *zserv_find_client(uint8_t proto, unsigned short instance);

/*
 * Retrieve a client by its protocol, instance number, and session id.
 *
 * proto
 *    protocol number
 *
 * instance
 *    instance number
 *
 * session_id
 *    session id
 *
 * Returns:
 *    The Zebra API client.
 */
struct zserv *zserv_find_client_session(uint8_t proto, unsigned short instance,
					uint32_t session_id);

/*
 * Retrieve a client object by the complete tuple of
 * {protocol, instance, session}. This version supports use
 * from a different pthread: the object will be returned marked
 * in-use. The caller *must* release the client object with the
 * release_client() api, to ensure that the in-use marker is cleared properly.
 *
 * Returns:
 *    The Zebra API client.
 */
extern struct zserv *zserv_acquire_client(uint8_t proto,
					  unsigned short instance,
					  uint32_t session_id);

/*
 * Release a client object that was acquired with the acquire_client() api.
 * After this has been called, the pointer must not be used - it may be freed
 * in another pthread if the client has closed.
 */
extern void zserv_release_client(struct zserv *client);

/*
 * Close a client.
 *
 * Kills a client's thread, removes the client from the client list and cleans
 * up its resources.
 *
 * client
 *    the client to close
 */
extern void zserv_close_client(struct zserv *client);

/*
 * Free memory for a zserv client object - note that this does not
 * clean up the internal allocations associated with the zserv client,
 * this just free the struct's memory.
 */
void zserv_client_delete(struct zserv *client);

/*
 * Log a ZAPI message hexdump.
 *
 * errmsg
 *    Error message to include with packet hexdump
 *
 * msg
 *    Message to log
 *
 * hdr
 *    Message header
 */
void zserv_log_message(const char *errmsg, struct stream *msg,
		       struct zmsghdr *hdr);

/* TODO */
__attribute__((__noreturn__)) void zebra_finalize(struct event *event);

/*
 * Graceful restart functions.
 */
extern int zebra_gr_client_disconnect(struct zserv *client);
extern void zebra_gr_client_reconnect(struct zserv *client);
extern void zebra_gr_stale_client_cleanup(struct list *client_list);
extern void zread_client_capabilities(struct zserv *client, struct zmsghdr *hdr,
				      struct stream *msg,
				      struct zebra_vrf *zvrf);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_ZEBRA_H */
