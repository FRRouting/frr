/*
 * EIGRP Daemon Program.
 * Copyright (C) 2013-2014
 * Authors:
 *   Donnie Savage
 *   Jan Janovic
 *   Matej Perina
 *   Peter Orsag
 *   Peter Paluch
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "thread.h"
#include "vty.h"
#include "command.h"
#include "linklist.h"
#include "prefix.h"
#include "table.h"
#include "if.h"
#include "memory.h"
#include "stream.h"
#include "log.h"
#include "sockunion.h" /* for inet_aton () */
#include "zclient.h"
#include "plist.h"
#include "sockopt.h"
#include "keychain.h"
#include "libfrr.h"

#include "eigrpd/eigrp_structs.h"
#include "eigrpd/eigrpd.h"
#include "eigrpd/eigrp_interface.h"
#include "eigrpd/eigrp_zebra.h"
#include "eigrpd/eigrp_vty.h"
#include "eigrpd/eigrp_neighbor.h"
#include "eigrpd/eigrp_packet.h"
#include "eigrpd/eigrp_network.h"
#include "eigrpd/eigrp_topology.h"
#include "eigrpd/eigrp_memory.h"

DEFINE_QOBJ_TYPE(eigrp)

static struct eigrp_master eigrp_master;

struct eigrp_master *eigrp_om;

static void eigrp_delete(struct eigrp *);
static struct eigrp *eigrp_new(const char *);
static void eigrp_add(struct eigrp *);

extern struct zclient *zclient;
extern struct in_addr router_id_zebra;


/*
 * void eigrp_router_id_update(struct eigrp *eigrp)
 *
 * Description:
 * update routerid associated with this instance of EIGRP.
 * If the id changes, then call if_update for each interface
 * to resync the topology database with all neighbors
 *
 * Select the router ID based on these priorities:
 *   1. Statically assigned router ID is always the first choice.
 *   2. If there is no statically assigned router ID, then try to stick
 *      with the most recent value, since changing router ID's is very
 *      disruptive.
 *   3. Last choice: just go with whatever the zebra daemon recommends.
 *
 * Note:
 * router id for EIGRP is really just a 32 bit number. Cisco historically
 * displays it in dotted decimal notation, and will pickup an IP address
 * from an interface so it can be 'auto-configed" to a uniqe value
 *
 * This does not work for IPv6, and to make the code simpler, its
 * stored and processed internerall as a 32bit number
 */
void eigrp_router_id_update(struct eigrp *eigrp)
{
	struct vrf *vrf = vrf_lookup_by_id(VRF_DEFAULT);
	struct interface *ifp;
	uint32_t router_id, router_id_old;

	router_id_old = eigrp->router_id;

	if (eigrp->router_id_static != 0)
		router_id = eigrp->router_id_static;

	else if (eigrp->router_id != 0)
		router_id = eigrp->router_id;

	else
		router_id = router_id_zebra.s_addr;

	eigrp->router_id = router_id;
	if (router_id_old != router_id) {
		//      if (IS_DEBUG_EIGRP_EVENT)
		//        zlog_debug("Router-ID[NEW:%s]: Update",
		//        inet_ntoa(eigrp->router_id));

		/* update eigrp_interface's */
		FOR_ALL_INTERFACES (vrf, ifp)
			eigrp_if_update(ifp);
	}
}

void eigrp_master_init()
{
	struct timeval tv;

	memset(&eigrp_master, 0, sizeof(struct eigrp_master));

	eigrp_om = &eigrp_master;
	eigrp_om->eigrp = list_new();

	monotime(&tv);
	eigrp_om->start_time = tv.tv_sec;
}

/* Allocate new eigrp structure. */
static struct eigrp *eigrp_new(const char *AS)
{
	struct eigrp *eigrp = XCALLOC(MTYPE_EIGRP_TOP, sizeof(struct eigrp));
	int eigrp_socket;

	/* init information relevant to peers */
	eigrp->vrid = 0;
	eigrp->AS = atoi(AS);
	eigrp->router_id = 0L;
	eigrp->router_id_static = 0L;
	eigrp->sequence_number = 1;

	/*Configure default K Values for EIGRP Process*/
	eigrp->k_values[0] = EIGRP_K1_DEFAULT;
	eigrp->k_values[1] = EIGRP_K2_DEFAULT;
	eigrp->k_values[2] = EIGRP_K3_DEFAULT;
	eigrp->k_values[3] = EIGRP_K4_DEFAULT;
	eigrp->k_values[4] = EIGRP_K5_DEFAULT;
	eigrp->k_values[5] = EIGRP_K6_DEFAULT;

	/* init internal data structures */
	eigrp->eiflist = list_new();
	eigrp->passive_interface_default = EIGRP_IF_ACTIVE;
	eigrp->networks = eigrp_topology_new();

	if ((eigrp_socket = eigrp_sock_init()) < 0) {
		zlog_err(
			"eigrp_new: fatal error: eigrp_sock_init was unable to open "
			"a socket");
		exit(1);
	}

	eigrp->fd = eigrp_socket;
	eigrp->maxsndbuflen = getsockopt_so_sendbuf(eigrp->fd);

	if ((eigrp->ibuf = stream_new(EIGRP_PACKET_MAX_LEN + 1)) == NULL) {
		zlog_err(
			"eigrp_new: fatal error: stream_new (%u) failed allocating ibuf",
			EIGRP_PACKET_MAX_LEN + 1);
		exit(1);
	}

	eigrp->t_read = NULL;
	thread_add_read(master, eigrp_read, eigrp, eigrp->fd, &eigrp->t_read);
	eigrp->oi_write_q = list_new();

	eigrp->topology_table = route_table_init();

	eigrp->neighbor_self = eigrp_nbr_new(NULL);
	eigrp->neighbor_self->src.s_addr = INADDR_ANY;

	eigrp->variance = EIGRP_VARIANCE_DEFAULT;
	eigrp->max_paths = EIGRP_MAX_PATHS_DEFAULT;

	eigrp->serno = 0;
	eigrp->serno_last_update = 0;
	eigrp->topology_changes_externalIPV4 = list_new();
	eigrp->topology_changes_internalIPV4 = list_new();

	eigrp->list[EIGRP_FILTER_IN] = NULL;
	eigrp->list[EIGRP_FILTER_OUT] = NULL;

	eigrp->prefix[EIGRP_FILTER_IN] = NULL;
	eigrp->prefix[EIGRP_FILTER_OUT] = NULL;

	eigrp->routemap[EIGRP_FILTER_IN] = NULL;
	eigrp->routemap[EIGRP_FILTER_OUT] = NULL;

	QOBJ_REG(eigrp, eigrp);
	return eigrp;
}

static void eigrp_add(struct eigrp *eigrp)
{
	listnode_add(eigrp_om->eigrp, eigrp);
}

static void eigrp_delete(struct eigrp *eigrp)
{
	listnode_delete(eigrp_om->eigrp, eigrp);
}

struct eigrp *eigrp_get(const char *AS)
{
	struct eigrp *eigrp;

	eigrp = eigrp_lookup();
	if (eigrp == NULL) {
		eigrp = eigrp_new(AS);
		eigrp_add(eigrp);
	}

	return eigrp;
}

/* Shut down the entire process */
void eigrp_terminate(void)
{
	struct eigrp *eigrp;
	struct listnode *node, *nnode;

	/* shutdown already in progress */
	if (CHECK_FLAG(eigrp_om->options, EIGRP_MASTER_SHUTDOWN))
		return;

	SET_FLAG(eigrp_om->options, EIGRP_MASTER_SHUTDOWN);

	for (ALL_LIST_ELEMENTS(eigrp_om->eigrp, node, nnode, eigrp))
		eigrp_finish(eigrp);

	frr_fini();
}

void eigrp_finish(struct eigrp *eigrp)
{
	eigrp_finish_final(eigrp);

	/* eigrp being shut-down? If so, was this the last eigrp instance? */
	if (CHECK_FLAG(eigrp_om->options, EIGRP_MASTER_SHUTDOWN)
	    && (listcount(eigrp_om->eigrp) == 0)) {
		if (zclient) {
			zclient_stop(zclient);
			zclient_free(zclient);
		}
		exit(0);
	}

	return;
}

/* Final cleanup of eigrp instance */
void eigrp_finish_final(struct eigrp *eigrp)
{
	struct eigrp_interface *ei;
	struct eigrp_neighbor *nbr;
	struct listnode *node, *nnode, *node2, *nnode2;

	for (ALL_LIST_ELEMENTS(eigrp->eiflist, node, nnode, ei)) {
		for (ALL_LIST_ELEMENTS(ei->nbrs, node2, nnode2, nbr))
			eigrp_nbr_delete(nbr);
		eigrp_if_free(ei, INTERFACE_DOWN_BY_FINAL);
	}

	THREAD_OFF(eigrp->t_write);
	THREAD_OFF(eigrp->t_read);
	close(eigrp->fd);

	list_delete_and_null(&eigrp->eiflist);
	list_delete_and_null(&eigrp->oi_write_q);

	eigrp_topology_cleanup(eigrp->topology_table);
	eigrp_topology_free(eigrp->topology_table);

	eigrp_nbr_delete(eigrp->neighbor_self);

	list_delete_and_null(&eigrp->topology_changes_externalIPV4);
	list_delete_and_null(&eigrp->topology_changes_internalIPV4);

	eigrp_delete(eigrp);

	XFREE(MTYPE_EIGRP_TOP, eigrp);
}

/*Look for existing eigrp process*/
struct eigrp *eigrp_lookup(void)
{
	if (listcount(eigrp_om->eigrp) == 0)
		return NULL;

	return listgetdata(listhead(eigrp_om->eigrp));
}
