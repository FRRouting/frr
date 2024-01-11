// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2017 Cumulus Networks Inc.
 *                    Donald Sharp
 *
 * This file is part of FRR
 */

#include <zebra.h>
#include <fcntl.h>

#include "qobj.h"
#include "vty.h"
#include "stream.h"
#include "privs.h"
#include "memory.h"
#include "queue.h"
#include "filter.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_open.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_network.h"

/* need these to link in libbgp */
struct zebra_privs_t bgpd_privs = {};
struct event_loop *master = NULL;

static struct bgp *bgp;
static as_t asn = 100;

extern int bgp_read_packet(struct peer *peer);

/*
 * This file is intended to be used as input for some sort of
 * fuzzer.  Specifically I had afl in mind when I wrote
 * this code.
 */
int main(int argc, char *argv[])
{
	struct peer *peer;
	int i, j;
	struct event t;

	qobj_init();
	bgp_attr_init();
	master = event_master_create(NULL);
	bgp_master_init(master, BGP_SOCKET_SNDBUF_SIZE, list_new());
	vrf_init(NULL, NULL, NULL, NULL);
	bgp_option_set(BGP_OPT_NO_LISTEN);

	if (bgp_get(&bgp, &asn, NULL, BGP_INSTANCE_TYPE_DEFAULT, NULL,
		    ASNOTATION_PLAIN) < 0)
		return -1;

	peer = peer_create_accept(bgp);
	peer->host = (char *)"foo";

	for (i = AFI_IP; i < AFI_MAX; i++)
		for (j = SAFI_UNICAST; j < SAFI_MAX; j++) {
			peer->afc[i][j] = 1;
			peer->afc_adv[i][j] = 1;
		}

	SET_FLAG(peer->cap, PEER_CAP_DYNAMIC_ADV);
	peer->connection = bgp_peer_connection_new(peer);
	peer->connection->status = Established;

	peer->connection->fd = open(argv[1], O_RDONLY | O_NONBLOCK);
	t.arg = peer;
	peer->connection->t_read = &t;

	// printf("bgp_read_packet returns: %d\n", bgp_read(&t));
}
