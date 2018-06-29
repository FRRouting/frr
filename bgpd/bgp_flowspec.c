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
#include "bgpd/bgp_flowspec_util.h"
#include "bgpd/bgp_flowspec_private.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_debug.h"

static int bgp_fs_nlri_validate(uint8_t *nlri_content, uint32_t len)
{
	uint32_t offset = 0;
	int type;
	int ret = 0, error = 0;

	while (offset < len-1) {
		type = nlri_content[offset];
		offset++;
		switch (type) {
		case FLOWSPEC_DEST_PREFIX:
		case FLOWSPEC_SRC_PREFIX:
			ret = bgp_flowspec_ip_address(
						BGP_FLOWSPEC_VALIDATE_ONLY,
						nlri_content + offset,
						len - offset, NULL, &error);
			break;
		case FLOWSPEC_IP_PROTOCOL:
		case FLOWSPEC_PORT:
		case FLOWSPEC_DEST_PORT:
		case FLOWSPEC_SRC_PORT:
		case FLOWSPEC_ICMP_TYPE:
		case FLOWSPEC_ICMP_CODE:
			ret = bgp_flowspec_op_decode(BGP_FLOWSPEC_VALIDATE_ONLY,
						   nlri_content + offset,
						   len - offset, NULL, &error);
			break;
		case FLOWSPEC_TCP_FLAGS:
		case FLOWSPEC_FRAGMENT:
			ret = bgp_flowspec_bitmask_decode(
						   BGP_FLOWSPEC_VALIDATE_ONLY,
						   nlri_content + offset,
						   len - offset, NULL, &error);
			break;
		case FLOWSPEC_PKT_LEN:
		case FLOWSPEC_DSCP:
			ret = bgp_flowspec_op_decode(
						BGP_FLOWSPEC_VALIDATE_ONLY,
						nlri_content + offset,
						len - offset, NULL, &error);
			break;
		default:
			error = -1;
			break;
		}
		offset += ret;
		if (error < 0)
			break;
	}
	return error;
}

int bgp_nlri_parse_flowspec(struct peer *peer, struct attr *attr,
			    struct bgp_nlri *packet, int withdraw)
{
	uint8_t *pnt;
	uint8_t *lim;
	afi_t afi;
	safi_t safi;
	int psize = 0;
	uint8_t rlen;
	struct prefix p;
	int ret;
	void *temp;

	/* Start processing the NLRI - there may be multiple in the MP_REACH */
	pnt = packet->nlri;
	lim = pnt + packet->length;
	afi = packet->afi;
	safi = packet->safi;

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
		if (bgp_fs_nlri_validate(pnt, psize) < 0) {
			zlog_err("Bad flowspec format or NLRI options not supported");
			return -1;
		}
		p.family = AF_FLOWSPEC;
		p.prefixlen = 0;
		/* Flowspec encoding is in bytes */
		p.u.prefix_flowspec.prefixlen = psize;
		temp = XCALLOC(MTYPE_TMP, psize);
		memcpy(temp, pnt, psize);
		p.u.prefix_flowspec.ptr = (uintptr_t) temp;

		if (BGP_DEBUG(flowspec, FLOWSPEC)) {
			char return_string[BGP_FLOWSPEC_NLRI_STRING_MAX];
			char local_string[BGP_FLOWSPEC_NLRI_STRING_MAX * 2];
			char ec_string[BGP_FLOWSPEC_NLRI_STRING_MAX];
			char *s = NULL;

			bgp_fs_nlri_get_string((unsigned char *)
					       p.u.prefix_flowspec.ptr,
					       p.u.prefix_flowspec.prefixlen,
					       return_string,
					       NLRI_STRING_FORMAT_MIN, NULL);
			snprintf(ec_string, sizeof(ec_string),
				 "EC{none}");
			if (attr && attr->ecommunity) {
				s = ecommunity_ecom2str(attr->ecommunity,
						ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
				snprintf(ec_string, sizeof(ec_string),
					 "EC{%s}",
					s == NULL ? "none" : s);

				if (s)
					ecommunity_strfree(&s);
			}
			snprintf(local_string, sizeof(local_string),
				 "FS Rx %s %s %s %s", withdraw ?
				 "Withdraw":"Update",
				 afi2str(afi), return_string,
				 attr != NULL ? ec_string : "");
			zlog_info("%s", local_string);
		}
		/* Process the route. */
		if (!withdraw)
			ret = bgp_update(peer, &p, 0, attr,
					 afi, safi,
					 ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL,
					 NULL, NULL, 0, 0, NULL);
		else
			ret = bgp_withdraw(peer, &p, 0, attr,
					   afi, safi,
					   ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL,
					   NULL, NULL, 0, NULL);
		if (ret) {
			zlog_err("Flowspec NLRI failed to be %s.",
				 attr ? "added" : "withdrawn");
			return -1;
		}
	}
	return 0;
}
