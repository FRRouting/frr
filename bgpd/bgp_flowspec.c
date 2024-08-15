// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP FlowSpec for packet handling
 * Portions:
 *     Copyright (C) 2017 ChinaTelecom SDN Group
 *     Copyright (C) 2018 6WIND
 */

#include <zebra.h>
#include <math.h>

#include "prefix.h"
#include "lib_errors.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_flowspec.h"
#include "bgpd/bgp_flowspec_util.h"
#include "bgpd/bgp_flowspec_private.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_errors.h"

static int bgp_fs_nlri_validate(uint8_t *nlri_content, uint32_t len,
				afi_t afi)
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
						len - offset, NULL, &error,
						afi, NULL);
			break;
		case FLOWSPEC_FLOW_LABEL:
			if (afi == AFI_IP)
				return -1;
			ret = bgp_flowspec_op_decode(BGP_FLOWSPEC_VALIDATE_ONLY,
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
			    struct bgp_nlri *packet, bool withdraw)
{
	uint8_t *pnt;
	uint8_t *lim;
	afi_t afi;
	safi_t safi;
	int psize = 0;
	struct prefix p;
	void *temp;

	/* Start processing the NLRI - there may be multiple in the MP_REACH */
	pnt = packet->nlri;
	lim = pnt + packet->length;
	afi = packet->afi;
	safi = packet->safi;

	/*
	 * All other AFI/SAFI's treat no attribute as a implicit
	 * withdraw.  Flowspec should as well.
	 */
	if (!attr)
		withdraw = true;

	if (packet->length >= FLOWSPEC_NLRI_SIZELIMIT_EXTENDED) {
		flog_err(EC_BGP_FLOWSPEC_PACKET,
			 "BGP flowspec nlri length maximum reached (%u)",
			 packet->length);
		return BGP_NLRI_PARSE_ERROR_FLOWSPEC_NLRI_SIZELIMIT;
	}

	for (; pnt < lim; pnt += psize) {
		/* Clear prefix structure. */
		memset(&p, 0, sizeof(p));

		/* All FlowSpec NLRI begin with length. */
		if (pnt + 1 > lim)
			return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;

		psize = *pnt++;
		if (psize >= FLOWSPEC_NLRI_SIZELIMIT) {
			psize &= 0x0f;
			psize = psize << 8;
			psize |= *pnt++;
		}
		/* When packet overflow occur return immediately. */
		if (pnt + psize > lim) {
			flog_err(
				EC_BGP_FLOWSPEC_PACKET,
				"Flowspec NLRI length inconsistent ( size %u seen)",
				psize);
			return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;
		}

		if (psize == 0) {
			flog_err(EC_BGP_FLOWSPEC_PACKET,
				 "Flowspec NLRI length 0 which makes no sense");
			return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;
		}

		if (bgp_fs_nlri_validate(pnt, psize, afi) < 0) {
			flog_err(
				EC_BGP_FLOWSPEC_PACKET,
				"Bad flowspec format or NLRI options not supported");
			return BGP_NLRI_PARSE_ERROR_FLOWSPEC_BAD_FORMAT;
		}
		p.family = AF_FLOWSPEC;
		p.prefixlen = 0;
		/* Flowspec encoding is in bytes */
		p.u.prefix_flowspec.prefixlen = psize;
		p.u.prefix_flowspec.family = afi2family(afi);
		temp = XCALLOC(MTYPE_TMP, psize);
		memcpy(temp, pnt, psize);
		p.u.prefix_flowspec.ptr = (uintptr_t) temp;

		if (BGP_DEBUG(flowspec, FLOWSPEC)) {
			char return_string[BGP_FLOWSPEC_NLRI_STRING_MAX];
			char local_string[BGP_FLOWSPEC_NLRI_STRING_MAX*2+16];
			char ec_string[BGP_FLOWSPEC_NLRI_STRING_MAX];
			char *s = NULL;

			bgp_fs_nlri_get_string((unsigned char *)
					       p.u.prefix_flowspec.ptr,
					       p.u.prefix_flowspec.prefixlen,
					       return_string,
					       NLRI_STRING_FORMAT_MIN, NULL,
					       afi);
			snprintf(ec_string, sizeof(ec_string),
				 "EC{none}");
			if (attr && bgp_attr_get_ecommunity(attr)) {
				s = ecommunity_ecom2str(
					bgp_attr_get_ecommunity(attr),
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
		if (!withdraw) {
			bgp_update(peer, &p, 0, attr, afi, safi,
				   ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, NULL,
				   NULL, 0, 0, NULL);
		} else {
			bgp_withdraw(peer, &p, 0, afi, safi, ZEBRA_ROUTE_BGP,
				     BGP_ROUTE_NORMAL, NULL, NULL, 0);
		}

		XFREE(MTYPE_TMP, temp);
	}
	return BGP_NLRI_PARSE_OK;
}
