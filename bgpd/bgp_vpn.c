/* VPN Related functions
 * Copyright (C) 2017 6WIND
 *
 * This file is part of FRRouting
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

#include <zebra.h>
#include "command.h"
#include "prefix.h"
#include "lib/json.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_vpn.h"

int show_adj_route_vpn(struct vty *vty, struct peer *peer,
		       struct prefix_rd *prd, afi_t afi, safi_t safi,
		       uint8_t use_json)
{
	struct bgp *bgp;
	struct bgp_table *table;
	struct bgp_node *rn;
	struct bgp_node *rm;
	struct attr *attr;
	int rd_header;
	int header = 1;
	json_object *json = NULL;
	json_object *json_scode = NULL;
	json_object *json_ocode = NULL;
	json_object *json_routes = NULL;
	json_object *json_array = NULL;

	bgp = bgp_get_default();
	if (bgp == NULL) {
		if (!use_json)
			vty_out(vty, "No BGP process is configured\n");
		else
			vty_out(vty, "{}\n");
		return CMD_WARNING;
	}

	if (use_json) {
		json_scode = json_object_new_object();
		json_ocode = json_object_new_object();
		json_routes = json_object_new_object();
		json = json_object_new_object();

		json_object_string_add(json_scode, "suppressed", "s");
		json_object_string_add(json_scode, "damped", "d");
		json_object_string_add(json_scode, "history", "h");
		json_object_string_add(json_scode, "valid", "*");
		json_object_string_add(json_scode, "best", ">");
		json_object_string_add(json_scode, "internal", "i");

		json_object_string_add(json_ocode, "igp", "i");
		json_object_string_add(json_ocode, "egp", "e");
		json_object_string_add(json_ocode, "incomplete", "?");
	}

	for (rn = bgp_table_top(bgp->rib[afi][SAFI_MPLS_VPN]); rn;
	     rn = bgp_route_next(rn)) {
		if (prd && memcmp(rn->p.u.val, prd->val, 8) != 0)
			continue;

		if ((table = rn->info) != NULL) {
			if (use_json)
				json_array = json_object_new_array();
			else
				json_array = NULL;

			rd_header = 1;

			for (rm = bgp_table_top(table); rm;
			     rm = bgp_route_next(rm)) {
				if ((attr = rm->info) != NULL) {
					if (header) {
						if (use_json) {
							json_object_int_add(
								json,
								"bgpTableVersion",
								0);
							json_object_string_add(
								json,
								"bgpLocalRouterId",
								inet_ntoa(
									bgp->router_id));
							json_object_object_add(
								json,
								"bgpStatusCodes",
								json_scode);
							json_object_object_add(
								json,
								"bgpOriginCodes",
								json_ocode);
						} else {
							vty_out(vty,
								"BGP table version is 0, local router ID is %s\n",
								inet_ntoa(
									bgp->router_id));
							vty_out(vty,
								"Status codes: s suppressed, d damped, h history, * valid, > best, i - internal\n");
							vty_out(vty,
								"Origin codes: i - IGP, e - EGP, ? - incomplete\n\n");
							vty_out(vty, V4_HEADER);
						}
						header = 0;
					}

					if (rd_header) {
						uint16_t type;
						struct rd_as rd_as = {0};
						struct rd_ip rd_ip = {0};
#if ENABLE_BGP_VNC
						struct rd_vnc_eth rd_vnc_eth = {
							0};
#endif
						uint8_t *pnt;

						pnt = rn->p.u.val;

						/* Decode RD type. */
						type = decode_rd_type(pnt);
						/* Decode RD value. */
						if (type == RD_TYPE_AS)
							decode_rd_as(pnt + 2,
								     &rd_as);
						else if (type == RD_TYPE_AS4)
							decode_rd_as4(pnt + 2,
								      &rd_as);
						else if (type == RD_TYPE_IP)
							decode_rd_ip(pnt + 2,
								     &rd_ip);
#if ENABLE_BGP_VNC
						else if (type
							 == RD_TYPE_VNC_ETH)
							decode_rd_vnc_eth(
								pnt,
								&rd_vnc_eth);
#endif

						if (use_json) {
							char buffer[BUFSIZ];
							if (type == RD_TYPE_AS
							    || type == RD_TYPE_AS4)
								sprintf(buffer,
									"%u:%d",
									rd_as.as,
									rd_as.val);
							else if (type
								 == RD_TYPE_IP)
								sprintf(buffer,
									"%s:%d",
									inet_ntoa(
										rd_ip.ip),
									rd_ip.val);
							json_object_string_add(
								json_routes,
								"routeDistinguisher",
								buffer);
						} else {
							vty_out(vty,
								"Route Distinguisher: ");

							if (type == RD_TYPE_AS
							    || type == RD_TYPE_AS4)
								vty_out(vty,
									"%u:%d",
									rd_as.as,
									rd_as.val);
							else if (type
								 == RD_TYPE_IP)
								vty_out(vty,
									"%s:%d",
									inet_ntoa(
										rd_ip.ip),
									rd_ip.val);
#if ENABLE_BGP_VNC
							else if (
								type
								== RD_TYPE_VNC_ETH)
								vty_out(vty,
									"%u:%02x:%02x:%02x:%02x:%02x:%02x",
									rd_vnc_eth
										.local_nve_id,
									rd_vnc_eth
										.macaddr
										.octet[0],
									rd_vnc_eth
										.macaddr
										.octet[1],
									rd_vnc_eth
										.macaddr
										.octet[2],
									rd_vnc_eth
										.macaddr
										.octet[3],
									rd_vnc_eth
										.macaddr
										.octet[4],
									rd_vnc_eth
										.macaddr
										.octet[5]);
#endif

							vty_out(vty, "\n");
						}
						rd_header = 0;
					}
					if (use_json) {
						char buf_a[BUFSIZ];
						char buf_b[BUFSIZ];

						sprintf(buf_a, "%s/%d",
							inet_ntop(rm->p.family,
								  rm->p.u.val,
								  buf_b,
								  BUFSIZ),
							rm->p.prefixlen);
						json_object_object_add(
							json_routes, buf_a,
							json_array);
					} else {
						route_vty_out_tmp(
							vty, &rm->p, attr,
							SAFI_MPLS_VPN, use_json,
							json_array);
					}
				}
			}
		}
	}
	if (use_json) {
		json_object_object_add(json, "routes", json_routes);
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}
	return CMD_SUCCESS;
}
