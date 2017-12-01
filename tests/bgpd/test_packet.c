/*
 * Copyright (C) 2017 Cumulus Networks Inc.
 *                    Donald Sharp
 *
 * This file is part of FRR
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

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

/* need these to link in libbgp */
struct zebra_privs_t *bgpd_privs = NULL;
struct thread_master *master = NULL;

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
	struct thread t;

	qobj_init();
	bgp_attr_init();
	master = thread_master_create(NULL);
	bgp_master_init(master);
	vrf_init(NULL, NULL, NULL, NULL);
	bgp_option_set(BGP_OPT_NO_LISTEN);

	if (bgp_get(&bgp, &asn, NULL, BGP_INSTANCE_TYPE_DEFAULT))
		return -1;

	peer = peer_create_accept(bgp);
	peer->host = (char *)"foo";

	for (i = AFI_IP; i < AFI_MAX; i++)
		for (j = SAFI_UNICAST; j < SAFI_MAX; j++) {
			peer->afc[i][j] = 1;
			peer->afc_adv[i][j] = 1;
		}

	SET_FLAG(peer->cap, PEER_CAP_DYNAMIC_ADV);
	peer->status = Established;

        peer->fd = open(argv[1], O_RDONLY|O_NONBLOCK);
	t.arg = peer;
	peer->t_read = &t;

	// printf("bgp_read_packet returns: %d\n", bgp_read(&t));
}
