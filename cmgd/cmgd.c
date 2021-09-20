/* Centralised Management Daemon program
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */


// #include "prefix.h"
#include "thread.h"
#include "buffer.h"
#include "stream.h"
#include "ringbuf.h"
#include "command.h"
#include "sockunion.h"
#include "sockopt.h"
#include "network.h"
#include "memory.h"
// #include "filter.h"
// #include "routemap.h"
#include "log.h"
#include "plist.h"
#include "linklist.h"
#include "workqueue.h"
#include "queue.h"
// #include "zclient.h"
// #include "bfd.h"
#include "hash.h"
#include "jhash.h"
#include "table.h"
#include "lib/json.h"
#include "frr_pthread.h"
#include "bitfield.h"
#include "lib/md5.h"
#include "lib/typesafe.h"
#include "cmgd/cmgd.h"
#include "cmgd/cmgd_vty.h"
#include "cmgd/cmgd_bcknd_server.h"
#include "cmgd/cmgd_bcknd_adapter.h"
#include "cmgd/cmgd_frntnd_server.h"
#include "cmgd/cmgd_frntnd_adapter.h"
#include "cmgd/cmgd_db.h"
#include "cmgd/cmgd_memory.h"
#include "cmgd/cmgd_trxn.h"

// bool cmgd_debug_bcknd = true;
// bool cmgd_debug_frntnd = true;
// bool cmgd_debug_db = true;
// bool cmgd_debug_trxn = true;
bool cmgd_debug_bcknd = false;
bool cmgd_debug_frntnd = false;
bool cmgd_debug_db = false;
bool cmgd_debug_trxn = false;

/* CMGD process wide configuration.  */
static struct cmgd_master cmgd_master;

/* CMGD process wide configuration pointer to export.  */
struct cmgd_master *cm;

/* time_t value that is monotonicly increasing
 * and uneffected by adjustments to system clock
 */
time_t cmgd_clock(void)
{
	struct timeval tv;

	monotime(&tv);
	return tv.tv_sec;
}

void cmgd_master_init(struct thread_master *master, const int buffer_size,
		      struct list *addresses)
{
	qobj_init();

	memset(&cmgd_master, 0, sizeof(struct cmgd_master));

	cm = &cmgd_master;
	cm->cmgd = list_new();
	cm->listen_sockets = list_new();
	// cm->port = CMGD_PORT_DEFAULT;
	// cm->addresses = addresses;
	cm->master = master;
	cm->start_time = cmgd_clock();
	// cm->t_rmap_update = NULL;
	// cm->rmap_update_timer = RMAP_DEFAULT_UPDATE_TIMER;
	// cm->v_update_delay = CMGD_UPDATE_DELAY_DEF;
	// cm->v_establish_wait = CMGD_UPDATE_DELAY_DEF;
	cm->terminating = false;
	cm->socket_buffer = buffer_size;
	// cm->wait_for_fib = false;

	// SET_FLAG(cm->flags, BM_FLAG_SEND_EXTRA_DATA_TO_ZEBRA);

	// cmgd_mac_init();
	/* init the rd id space.
	   assign 0th index in the bitfield,
	   so that we start with id 1
	 */
	// bf_init(cm->rd_idspace, UINT16_MAX);
	// bf_assign_zero_index(cm->rd_idspace);

	/* mpls label dynamic allocation pool */
	// cmgd_lp_init(cm->master, &cm->labelpool);

	// cmgd_l3nhg_init();
	// cmgd_evpn_mh_init();
	// QOBJ_REG(bm, cmgd_master);
	cm->perf_stats_en = true;
}

static void cmgd_pthreads_init(void)
{
#if 0
	assert(!cmgd_pth_io);
	assert(!cmgd_pth_ka);

	struct frr_pthread_attr io = {
		.start = frr_pthread_attr_default.start,
		.stop = frr_pthread_attr_default.stop,
	};
	struct frr_pthread_attr ka = {
		.start = cmgd_keepalives_start,
		.stop = cmgd_keepalives_stop,
	};
	cmgd_pth_io = frr_pthread_new(&io, "CMGD I/O thread", "cmgd_io");
	cmgd_pth_ka = frr_pthread_new(&ka, "CMGD Keepalives thread", "cmgd_ka");
#endif
}

void cmgd_pthreads_run(void)
{
#if 0
	frr_pthread_run(cmgd_pth_io, NULL);
	frr_pthread_run(cmgd_pth_ka, NULL);

	/* Wait until threads are ready. */
	frr_pthread_wait_running(cmgd_pth_io);
	frr_pthread_wait_running(cmgd_pth_ka);
#endif
}

void cmgd_pthreads_finish(void)
{
	frr_pthread_stop_all();
}

void cmgd_init(void)
{

	/* allocates some vital data structures used by peer commands in
	 * vty_init */
	vty_init_cmgd_frntnd();

	/* pre-init pthreads */
	cmgd_pthreads_init();

	/* Initialize databases */
	cmgd_db_init(cm);

	/* Initialize CMGD Transaction module */
	cmgd_trxn_init(cm, cm->master);

	/* Initialize the CMGD Backend Adapter Module */
	cmgd_bcknd_adapter_init(cm->master);
	
	/* Initialize the CMGD Frontend Adapter Module */
	cmgd_frntnd_adapter_init(cm->master, cm);

	/* Start the CMGD Backend Server for clients to connect */
	cmgd_bcknd_server_init(cm->master);

	/* Start the CMGD Frontend Server for clients to connect */
	cmgd_frntnd_server_init(cm->master);

	/* CMGD VTY commands installation.  */
	cmgd_vty_init();
}

void cmgd_terminate(void)
{
#if 0
	struct cmgd *cmgd;
	struct peer *peer;
	struct listnode *node, *nnode;
	struct listnode *mnode, *mnnode;

	QOBJ_UNREG(bm);

	/* Close the listener sockets first as this prevents peers from
	 * attempting
	 * to reconnect on receiving the peer unconfig message. In the presence
	 * of a large number of peers this will ensure that no peer is left with
	 * a dangling connection
	 */
	/* reverse cmgd_master_init */
	cmgd_close();

	if (cm->listen_sockets)
		list_delete(&cm->listen_sockets);

	for (ALL_LIST_ELEMENTS(cm->cmgd, mnode, mnnode, cmgd))
		for (ALL_LIST_ELEMENTS(cmgd->peer, node, nnode, peer))
			if (peer->status == Established
			    || peer->status == OpenSent
			    || peer->status == OpenConfirm)
				cmgd_notify_send(peer, CMGD_NOTIFY_CEASE,
						CMGD_NOTIFY_CEASE_PEER_UNCONFIG);

	if (cm->t_rmap_update)
		CMGD_TIMER_OFF(cm->t_rmap_update);

	cmgd_mac_finish();
#endif

	cmgd_bcknd_server_destroy();
	cmgd_db_destroy();
}