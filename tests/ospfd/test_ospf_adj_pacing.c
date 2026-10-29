// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Regression test for RFC4222 R5 adjacency pacing: a neighbor waiting on
 * its interface's pacing queue must leave the queue when it is freed,
 * whichever path frees it.
 *
 * With "adjacency-pacing static 1", the first neighbor to reach TwoWay takes
 * the formation slot and the second one waits on oi->adj_pacing.queue. The
 * waiting neighbor is then freed with ospf_nbr_delete(), without KillNbr,
 * as ospf_qnbr_rekey_ptp_vlink() does for a quick neighbor. Killing the
 * first neighbor afterwards releases the slot and kicks the queue. If the
 * freed neighbor was left on the queue, the queue check below fails, and
 * under AddressSanitizer the kick also reports a use-after-free.
 */

#include <zebra.h>

#include "lib/if.h"
#include "lib/prefix.h"
#include "lib/privs.h"
#include "lib/table.h"
#include "lib/vrf.h"
#include "lib/vty.h"
#include "lib/zclient.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_packet.h"

/* need these to link in libfrrospf */
struct event_loop *master;
struct zebra_privs_t ospfd_privs;

DECLARE_LIST(ospf_pacing_queue, struct ospf_neighbor, pacing_link);

#define TEST_NAME "adj-pacing-free: a freed neighbor leaves the adjacency pacing queue"

static struct ospf_neighbor *add_neighbor(struct ospf_interface *oi, const char *addr,
					  const char *rid)
{
	struct ospf_header ospfh = {};
	struct ip iph = {};
	struct prefix p = {};
	struct ospf_neighbor *nbr;

	ospfh.version = OSPF_VERSION;
	ospfh.type = OSPF_MSG_HELLO;
	ospfh.area_id = oi->area->area_id;
	ospfh.auth_type = htons(OSPF_AUTH_NULL);
	inet_aton(rid, &ospfh.router_id);
	inet_aton(addr, &iph.ip_src);
	p.family = AF_INET;
	p.prefixlen = IPV4_MAX_BITLEN;
	p.u.prefix4 = iph.ip_src;

	nbr = ospf_nbr_get(oi, &ospfh, &iph, &p);
	OSPF_NSM_EVENT_EXECUTE(nbr, NSM_HelloReceived);
	OSPF_NSM_EVENT_EXECUTE(nbr, NSM_TwoWayReceived);
	return nbr;
}

static int fail(const char *why)
{
	printf("%s\n%s\nfailed!\n", TEST_NAME, why);
	return 1;
}

int main(int argc, char **argv)
{
	struct in_addr area_id = { .s_addr = OSPF_AREA_BACKBONE };
	struct ospf *ospf;
	struct ospf_area *area;
	struct interface *ifp;
	struct prefix *p;
	struct ospf_interface *oi;
	struct ospf_neighbor *active, *waiting;

	master = event_master_create(NULL);
	cmd_init(1);
	vty_init(master, false);
	zlog_aux_init("NONE: ", LOG_ERR);
	vrf_init(NULL, NULL, NULL, NULL);
	ospf_master_init(master);
	ospf_if_init();

	ospf = ospf_new_alloc(0, VRF_DEFAULT_NAME);
	area = ospf_area_new(ospf, area_id);
	listnode_add_sort(ospf->areas, area);
	inet_aton("192.0.2.1", &ospf->router_id);
	ospf->fd = socket(AF_INET, SOCK_DGRAM, 0); /* the loop never runs: writes stay queued */
	assert(ospf->fd >= 0);
	ospf_zclient = zclient_new(master, &zclient_options_default, NULL, 0);

	ifp = if_get_by_name("eth0", VRF_DEFAULT, VRF_DEFAULT_NAME);
	ifp->flags = IFF_UP | IFF_RUNNING;
	ifp->mtu = 1500;

	p = prefix_new();
	p->family = AF_INET;
	p->prefixlen = 24;
	inet_aton("10.0.0.1", &p->u.prefix4);

	oi = ospf_if_new(ospf, ifp, p);
	oi->area = area;
	oi->connected = connected_new();
	oi->connected->ifp = ifp;
	oi->connected->address = p;
	oi->type = OSPF_IFTYPE_POINTOPOINT;
	oi->state = ISM_PointToPoint;
	ospf_nbr_add_self(oi, ospf->router_id);

	/* "ip ospf adjacency-pacing static 1" */
	oi->adj_pacing.mode = OSPF_ADJ_PACING_STATIC;
	oi->adj_pacing.static_limit = 1;

	active = add_neighbor(oi, "10.0.0.2", "192.0.2.2");
	waiting = add_neighbor(oi, "10.0.0.3", "192.0.2.3");
	if (active->state != NSM_ExStart || oi->adj_pacing.in_progress != 1)
		return fail("first neighbor did not take the formation slot");
	if (waiting->state != NSM_TwoWay ||
	    !ospf_pacing_queue_member(&oi->adj_pacing.queue, waiting))
		return fail("second neighbor is not waiting on the pacing queue");

	/* Freed without KillNbr, as a re-keyed quick neighbor is. */
	ospf_nbr_delete(waiting);
	if (ospf_pacing_queue_count(&oi->adj_pacing.queue) != 0)
		return fail("freed neighbor is still on the pacing queue");

	/* Releasing the slot kicks the queue. */
	OSPF_NSM_EVENT_EXECUTE(active, NSM_KillNbr);
	if (oi->adj_pacing.in_progress != 0)
		return fail("formation slot was not released");

	printf("%s\nOK\n", TEST_NAME);
	return 0;
}
