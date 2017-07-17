/*
 *
 * Copyright 2009-2016, LabN Consulting, L.L.C.
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */


#include <errno.h>

#include "lib/zebra.h"
#include "lib/prefix.h"
#include "lib/table.h"
#include "lib/vty.h"
#include "lib/memory.h"
#include "lib/log.h"

#include "bgpd/bgpd.h"

#include "bgpd/rfapi/rfapi.h"
#include "bgpd/rfapi/rfapi_private.h"
#include "bgpd/rfapi/rfapi_descriptor_rfp_utils.h"
#include "bgpd/rfapi/vnc_debug.h"


void *rfapi_create_generic(struct rfapi_ip_addr *vn, struct rfapi_ip_addr *un)
{
	struct rfapi_descriptor *rfd;
	rfd = XCALLOC(MTYPE_RFAPI_DESC, sizeof(struct rfapi_descriptor));
	vnc_zlog_debug_verbose("%s: rfd=%p", __func__, rfd);
	rfd->vn_addr = *vn;
	rfd->un_addr = *un;
	return (void *)rfd;
}

/*------------------------------------------
 * rfapi_free_generic
 *
 * Compare two generic rfapi descriptors.
 *
 * input:
 *    grfd: rfapi descriptor returned by rfapi_open or rfapi_create_generic
 *
 * output:
 *
 * return value:
 *
 *------------------------------------------*/
void rfapi_free_generic(void *grfd)
{
	struct rfapi_descriptor *rfd;
	rfd = (struct rfapi_descriptor *)grfd;
	XFREE(MTYPE_RFAPI_DESC, rfd);
}


/*------------------------------------------
 * rfapi_compare_rfds
 *
 * Compare two generic rfapi descriptors.
 *
 * input:
 *    rfd1: rfapi descriptor returned by rfapi_open or rfapi_create_generic
 *    rfd2: rfapi descriptor returned by rfapi_open or rfapi_create_generic
 *
 * output:
 *
 * return value:
 *	0		Mismatch
 *	1		Match
 *------------------------------------------*/
int rfapi_compare_rfds(void *rfd1, void *rfd2)
{
	struct rfapi_descriptor *rrfd1, *rrfd2;
	int match = 0;

	rrfd1 = (struct rfapi_descriptor *)rfd1;
	rrfd2 = (struct rfapi_descriptor *)rfd2;

	if (rrfd1->vn_addr.addr_family == rrfd2->vn_addr.addr_family) {
		if (rrfd1->vn_addr.addr_family == AF_INET)
			match = IPV4_ADDR_SAME(&(rrfd1->vn_addr.addr.v4),
					       &(rrfd2->vn_addr.addr.v4));
		else
			match = IPV6_ADDR_SAME(&(rrfd1->vn_addr.addr.v6),
					       &(rrfd2->vn_addr.addr.v6));
	}

	/*
	 * If the VN addresses don't match in all forms,
	 * give up.
	 */
	if (!match)
		return 0;

	/*
	 * do the process again for the UN addresses.
	 */
	match = 0;
	if (rrfd1->un_addr.addr_family == rrfd2->un_addr.addr_family) {
		/* VN addresses match
		 * UN address families match
		 * now check the actual UN addresses
		 */
		if (rrfd1->un_addr.addr_family == AF_INET)
			match = IPV4_ADDR_SAME(&(rrfd1->un_addr.addr.v4),
					       &(rrfd2->un_addr.addr.v4));
		else
			match = IPV6_ADDR_SAME(&(rrfd1->un_addr.addr.v6),
					       &(rrfd2->un_addr.addr.v6));
	}
	return match;
}
