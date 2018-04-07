/*
 * BGP Label Pool - Manage label chunk allocations from zebra asynchronously
 *
 * Copyright (C) 2018 LabN Consulting, L.L.C.
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

#ifndef _FRR_BGP_LABELPOOL_H
#define _FRR_BGP_LABELPOOL_H

#include <zebra.h>

#include "mpls.h"

/*
 * Types used in bgp_lp_get for debug tracking; add more as needed
 */
#define LP_TYPE_VRF	0x00000001

struct labelpool {
	struct skiplist		*ledger;	/* all requests */
	struct skiplist		*inuse;		/* individual labels */
	struct list		*chunks;	/* granted by zebra */
	struct lp_fifo		*requests;	/* blocked on zebra */
	struct work_queue	*callback_q;
	uint32_t		pending_count;	/* requested from zebra */
};

extern void bgp_lp_init(struct thread_master *master, struct labelpool *pool);
extern void bgp_lp_finish(void);
extern void bgp_lp_get(int type, void *labelid,
	int (*cbfunc)(mpls_label_t label, void *labelid, bool allocated));
extern void bgp_lp_release(int type, void *labelid, mpls_label_t label);
extern void bgp_lp_event_chunk(uint8_t keep, uint32_t first, uint32_t last);
extern void bgp_lp_event_zebra_down(void);
extern void bgp_lp_event_zebra_up(void);

#endif /* _FRR_BGP_LABELPOOL_H */
