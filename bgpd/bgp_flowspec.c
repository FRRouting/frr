/* BGP FlowSpec for packet handling
 * Portions:
 *     Copyright (C) 2017 ChinaTelecom SDN Group
 *     Copyright (C) 2018 6WIND
 *
 * FRRouting is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRRouting is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "math.h"

#include <zebra.h>
#include "prefix.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_flowspec.h"
#include "bgpd/bgp_flowspec_private.h"

int bgp_nlri_parse_flowspec(struct peer *peer, struct attr *attr,
			    struct bgp_nlri *packet, int withdraw)
{
	uint8_t *pnt;
	uint8_t *lim;
	afi_t afi;
	int psize = 0;
	uint8_t rlen;
	struct prefix p;

	/* Start processing the NLRI - there may be multiple in the MP_REACH */
	pnt = packet->nlri;
	lim = pnt + packet->length;
	afi = packet->afi;

	if (afi == AFI_IP6) {
		zlog_err("BGP flowspec IPv6 not supported");
		return -1;
	}

	if (packet->length >= FLOWSPEC_NLRI_SIZELIMIT) {
		zlog_err("BGP flowspec nlri length maximum reached (%u)",
			 packet->length);
		return -1;
	}

	for (; pnt < lim; pnt += psize) {
		/* Clear prefix structure. */
		memset(&p, 0, sizeof(struct prefix));

		/* All FlowSpec NLRI begin with length. */
		if (pnt + 1 > lim)
			return -1;

		psize = rlen = *pnt++;

		/* When packet overflow occur return immediately. */
		if (pnt + psize > lim) {
			zlog_err("Flowspec NLRI length inconsistent ( size %u seen)",
				 psize);
			return -1;
		}
		/* TODO: validate prefix
		 * and add to FIB
		 */
	}
	return 0;
}
