// SPDX-License-Identifier: GPL-2.0-or-later
/* VPN Related functions
 * Copyright (C) 2017 6WIND
 *
 * This file is part of FRRouting
 */

#include <zebra.h>
#include "command.h"
#include "prefix.h"
#include "lib/json.h"
#include "lib/printfrr.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_vpn.h"
#include "bgpd/bgp_updgrp.h"

int show_adj_route_vpn(struct vty *vty, struct peer *peer,
		       struct prefix_rd *prd, afi_t afi, safi_t safi,
		       bool use_json)
{
	struct bgp *bgp;
	struct bgp_table *table;
	struct bgp_dest *dest;
	struct bgp_dest *rm;
	int rd_header;
	int header = 1;
	json_object *json = NULL;
	json_object *json_adv = NULL;
	json_object *json_routes = NULL;
	char rd_str[BUFSIZ];
	unsigned long output_count = 0;

	bgp = bgp_get_default();
	if (bgp == NULL) {
		if (!use_json)
			vty_out(vty, "No BGP process is configured\n");
		else
			vty_out(vty, "{}\n");
		return CMD_WARNING;
	}

	if (use_json) {
		json = json_object_new_object();
		json_adv = json_object_new_object();
	}

	for (dest = bgp_table_top(bgp->rib[afi][safi]); dest;
	     dest = bgp_route_next(dest)) {
		const struct prefix *dest_p = bgp_dest_get_prefix(dest);

		if (prd && memcmp(dest_p->u.val, prd->val, 8) != 0)
			continue;

		table = bgp_dest_get_bgp_table_info(dest);
		if (table == NULL)
			continue;

		/*
		 * Initialize variables for each RD
		 * All prefixes under an RD is aggregated within "json_routes"
		 */
		rd_header = 1;
		memset(rd_str, 0, sizeof(rd_str));
		json_routes = NULL;

		for (rm = bgp_table_top(table); rm; rm = bgp_route_next(rm)) {
			struct bgp_adj_out *adj = NULL;
			struct attr *attr = NULL;
			struct peer_af *paf = NULL;

			RB_FOREACH (adj, bgp_adj_out_rb, &rm->adj_out)
				SUBGRP_FOREACH_PEER (adj->subgroup, paf) {
					if (paf->peer != peer || !adj->attr)
						continue;

					attr = adj->attr;
					break;
			}

			if (bgp_dest_get_bgp_path_info(rm) == NULL)
				continue;

			if (!attr)
				continue;

			if (header) {
				if (use_json) {
					json_object_int_add(
						json, "bgpTableVersion", 0);
					json_object_string_addf(
						json, "bgpLocalRouterId",
						"%pI4", &bgp->router_id);
					json_object_int_add(
						json,
						"defaultLocPrf",
						bgp->default_local_pref);
					json_object_int_add(
						json, "localAS",
						bgp->as);
				} else {
					vty_out(vty,
						"BGP table version is 0, local router ID is %pI4\n",
						&bgp->router_id);
					vty_out(vty, "Default local pref %u, ",
						bgp->default_local_pref);
					vty_out(vty, "local AS %u\n", bgp->as);
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
#ifdef ENABLE_BGP_VNC
				struct rd_vnc_eth rd_vnc_eth = {0};
#endif
				const uint8_t *pnt;

				pnt = dest_p->u.val;

				/* Decode RD type. */
				type = decode_rd_type(pnt);
				/* Decode RD value. */
				if (type == RD_TYPE_AS)
					decode_rd_as(pnt + 2, &rd_as);
				else if (type == RD_TYPE_AS4)
					decode_rd_as4(pnt + 2, &rd_as);
				else if (type == RD_TYPE_IP)
					decode_rd_ip(pnt + 2, &rd_ip);
#ifdef ENABLE_BGP_VNC
				else if (type == RD_TYPE_VNC_ETH)
					decode_rd_vnc_eth(pnt, &rd_vnc_eth);
#endif
				if (use_json) {
					json_routes = json_object_new_object();

					if (type == RD_TYPE_AS
					    || type == RD_TYPE_AS4)
						snprintf(rd_str, sizeof(rd_str),
							 "%u:%d", rd_as.as,
							 rd_as.val);
					else if (type == RD_TYPE_IP)
						snprintfrr(rd_str,
							   sizeof(rd_str),
							   "%pI4:%d", &rd_ip.ip,
							   rd_ip.val);
					json_object_string_add(
						json_routes,
						"rd", rd_str);
				} else {
					vty_out(vty, "Route Distinguisher: ");

					if (type == RD_TYPE_AS
					    || type == RD_TYPE_AS4)
						vty_out(vty, "%u:%d", rd_as.as,
							rd_as.val);
					else if (type == RD_TYPE_IP)
						vty_out(vty, "%pI4:%d",
							&rd_ip.ip, rd_ip.val);
#ifdef ENABLE_BGP_VNC
					else if (type == RD_TYPE_VNC_ETH)
						vty_out(vty,
							"%u:%02x:%02x:%02x:%02x:%02x:%02x",
							rd_vnc_eth.local_nve_id,
							rd_vnc_eth.macaddr
								.octet[0],
							rd_vnc_eth.macaddr
								.octet[1],
							rd_vnc_eth.macaddr
								.octet[2],
							rd_vnc_eth.macaddr
								.octet[3],
							rd_vnc_eth.macaddr
								.octet[4],
							rd_vnc_eth.macaddr
								.octet[5]);
#endif

					vty_out(vty, "\n");
				}
				rd_header = 0;
			}
			route_vty_out_tmp(vty, bgp, rm, bgp_dest_get_prefix(rm),
					  attr, safi, use_json, json_routes,
					  false);
			output_count++;
		}

		if (use_json && json_routes)
			json_object_object_add(json_adv, rd_str, json_routes);
	}

	if (use_json) {
		json_object_object_add(json, "advertisedRoutes", json_adv);
		json_object_int_add(json,
			"totalPrefixCounter", output_count);
		vty_json(vty, json);
	} else
		vty_out(vty, "\nTotal number of prefixes %ld\n", output_count);

	return CMD_SUCCESS;
}
