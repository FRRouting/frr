/* Ethernet-VPN Packet and vty Processing File
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
#include "stream.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_vpn.h"
#include "bgpd/bgp_evpn_vty.h"
#include "bgpd/bgp_evpn.h"
#include "bgpd/bgp_evpn_private.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_lcommunity.h"
#include "bgpd/bgp_community.h"

#define SHOW_DISPLAY_STANDARD 0
#define SHOW_DISPLAY_TAGS 1
#define SHOW_DISPLAY_OVERLAY 2
#define VNI_STR_LEN 32

/*
 * Context for VNI hash walk - used by callbacks.
 */
struct vni_walk_ctx {
	struct bgp *bgp;
	struct vty *vty;
	struct in_addr vtep_ip;
	json_object *json;
	int detail;
};

static void display_vrf_import_rt(struct vty *vty, struct vrf_irt_node *irt,
				  json_object *json)
{
	uint8_t *pnt;
	uint8_t type, sub_type;
	struct ecommunity_as eas;
	struct ecommunity_ip eip;
	struct listnode *node, *nnode;
	struct bgp *tmp_bgp_vrf = NULL;
	json_object *json_rt = NULL;
	json_object *json_vrfs = NULL;
	char rt_buf[RT_ADDRSTRLEN];

	if (json) {
		json_rt = json_object_new_object();
		json_vrfs = json_object_new_array();
	}

	pnt = (uint8_t *)&irt->rt.val;
	type = *pnt++;
	sub_type = *pnt++;
	if (sub_type != ECOMMUNITY_ROUTE_TARGET)
		return;

	memset(&eas, 0, sizeof(eas));
	switch (type) {
	case ECOMMUNITY_ENCODE_AS:
		eas.as = (*pnt++ << 8);
		eas.as |= (*pnt++);
		ptr_get_be32(pnt, &eas.val);

		snprintf(rt_buf, RT_ADDRSTRLEN, "%u:%u", eas.as, eas.val);

		if (json)
			json_object_string_add(json_rt, "rt", rt_buf);
		else
			vty_out(vty, "Route-target: %s", rt_buf);

		break;

	case ECOMMUNITY_ENCODE_IP:
		memcpy(&eip.ip, pnt, 4);
		pnt += 4;
		eip.val = (*pnt++ << 8);
		eip.val |= (*pnt++);

		snprintf(rt_buf, RT_ADDRSTRLEN, "%s:%u", inet_ntoa(eip.ip),
			 eip.val);

		if (json)
			json_object_string_add(json_rt, "rt", rt_buf);
		else
			vty_out(vty, "Route-target: %s", rt_buf);

		break;

	case ECOMMUNITY_ENCODE_AS4:
		pnt = ptr_get_be32(pnt, &eas.val);
		eas.val = (*pnt++ << 8);
		eas.val |= (*pnt++);

		snprintf(rt_buf, RT_ADDRSTRLEN, "%u:%u", eas.as, eas.val);

		if (json)
			json_object_string_add(json_rt, "rt", rt_buf);
		else
			vty_out(vty, "Route-target: %s", rt_buf);

		break;

	default:
		return;
	}

	if (!json) {
		vty_out(vty,
			"\nList of VRFs importing routes with this route-target:\n");
	}

	for (ALL_LIST_ELEMENTS(irt->vrfs, node, nnode, tmp_bgp_vrf)) {
		if (json)
			json_object_array_add(
				json_vrfs,
				json_object_new_string(
					vrf_id_to_name(tmp_bgp_vrf->vrf_id)));
		else
			vty_out(vty, "  %s\n",
				vrf_id_to_name(tmp_bgp_vrf->vrf_id));
	}

	if (json) {
		json_object_object_add(json_rt, "vrfs", json_vrfs);
		json_object_object_add(json, rt_buf, json_rt);
	}
}

static void show_vrf_import_rt_entry(struct hash_bucket *bucket, void *args[])
{
	json_object *json = NULL;
	struct vty *vty = NULL;
	struct vrf_irt_node *irt = (struct vrf_irt_node *)bucket->data;

	vty = (struct vty *)args[0];
	json = (struct json_object *)args[1];

	display_vrf_import_rt(vty, irt, json);
}

static void display_import_rt(struct vty *vty, struct irt_node *irt,
			      json_object *json)
{
	uint8_t *pnt;
	uint8_t type, sub_type;
	struct ecommunity_as eas;
	struct ecommunity_ip eip;
	struct listnode *node, *nnode;
	struct bgpevpn *tmp_vpn;
	json_object *json_rt = NULL;
	json_object *json_vnis = NULL;
	char rt_buf[RT_ADDRSTRLEN];

	if (json) {
		json_rt = json_object_new_object();
		json_vnis = json_object_new_array();
	}

	/* TODO: This needs to go into a function */

	pnt = (uint8_t *)&irt->rt.val;
	type = *pnt++;
	sub_type = *pnt++;
	if (sub_type != ECOMMUNITY_ROUTE_TARGET)
		return;

	memset(&eas, 0, sizeof(eas));
	switch (type) {
	case ECOMMUNITY_ENCODE_AS:
		eas.as = (*pnt++ << 8);
		eas.as |= (*pnt++);
		ptr_get_be32(pnt, &eas.val);

		snprintf(rt_buf, RT_ADDRSTRLEN, "%u:%u", eas.as, eas.val);

		if (json)
			json_object_string_add(json_rt, "rt", rt_buf);
		else
			vty_out(vty, "Route-target: %s", rt_buf);

		break;

	case ECOMMUNITY_ENCODE_IP:
		memcpy(&eip.ip, pnt, 4);
		pnt += 4;
		eip.val = (*pnt++ << 8);
		eip.val |= (*pnt++);

		snprintf(rt_buf, RT_ADDRSTRLEN, "%s:%u", inet_ntoa(eip.ip),
			 eip.val);

		if (json)
			json_object_string_add(json_rt, "rt", rt_buf);
		else
			vty_out(vty, "Route-target: %s", rt_buf);

		break;

	case ECOMMUNITY_ENCODE_AS4:
		pnt = ptr_get_be32(pnt, &eas.val);
		eas.val = (*pnt++ << 8);
		eas.val |= (*pnt++);

		snprintf(rt_buf, RT_ADDRSTRLEN, "%u:%u", eas.as, eas.val);

		if (json)
			json_object_string_add(json_rt, "rt", rt_buf);
		else
			vty_out(vty, "Route-target: %s", rt_buf);

		break;

	default:
		return;
	}

	if (!json) {
		vty_out(vty,
			"\nList of VNIs importing routes with this route-target:\n");
	}

	for (ALL_LIST_ELEMENTS(irt->vnis, node, nnode, tmp_vpn)) {
		if (json)
			json_object_array_add(
				json_vnis, json_object_new_int(tmp_vpn->vni));
		else
			vty_out(vty, "  %u\n", tmp_vpn->vni);
	}

	if (json) {
		json_object_object_add(json_rt, "vnis", json_vnis);
		json_object_object_add(json, rt_buf, json_rt);
	}
}

static void show_import_rt_entry(struct hash_bucket *bucket, void *args[])
{
	json_object *json = NULL;
	struct vty *vty = NULL;
	struct irt_node *irt = (struct irt_node *)bucket->data;

	vty = args[0];
	json = args[1];

	display_import_rt(vty, irt, json);

	return;
}

static void bgp_evpn_show_route_rd_header(struct vty *vty,
					  struct bgp_node *rd_rn,
					  json_object *json,
					  char *rd_str, int len)
{
	uint16_t type;
	struct rd_as rd_as;
	struct rd_ip rd_ip;
	uint8_t *pnt;

	pnt = rd_rn->p.u.val;

	/* Decode RD type. */
	type = decode_rd_type(pnt);

	if (!json)
		vty_out(vty, "Route Distinguisher: ");

	switch (type) {
	case RD_TYPE_AS:
		decode_rd_as(pnt + 2, &rd_as);
		snprintf(rd_str, len, "%u:%d", rd_as.as, rd_as.val);
		if (json)
			json_object_string_add(json, "rd", rd_str);
		else
			vty_out(vty, "as2 %s\n", rd_str);
		break;

	case RD_TYPE_AS4:
		decode_rd_as4(pnt + 2, &rd_as);
		snprintf(rd_str, len, "%u:%d", rd_as.as, rd_as.val);
		if (json)
			json_object_string_add(json, "rd", rd_str);
		else
			vty_out(vty, "as4 %s\n", rd_str);
		break;

	case RD_TYPE_IP:
		decode_rd_ip(pnt + 2, &rd_ip);
		snprintf(rd_str, len, "%s:%d", inet_ntoa(rd_ip.ip),
			 rd_ip.val);
		if (json)
			json_object_string_add(json, "rd", rd_str);
		else
			vty_out(vty, "ip %s\n", rd_str);
		break;

	default:
		if (json) {
			snprintf(rd_str, len, "Unknown");
			json_object_string_add(json, "rd", rd_str);
		} else {
			snprintf(rd_str, len, "Unknown RD type");
			vty_out(vty, "ip %s\n", rd_str);
		}
		break;
	}
}

static void bgp_evpn_show_route_header(struct vty *vty, struct bgp *bgp,
				       uint64_t tbl_ver, json_object *json)
{
	char ri_header[] =
		"   Network          Next Hop            Metric LocPrf Weight Path\n";

	if (json)
		return;

	vty_out(vty, "BGP table version is %" PRIu64 ", local router ID is %s\n",
		tbl_ver, inet_ntoa(bgp->router_id));
	vty_out(vty,
		"Status codes: s suppressed, d damped, h history, "
		"* valid, > best, i - internal\n");
	vty_out(vty, "Origin codes: i - IGP, e - EGP, ? - incomplete\n");
	vty_out(vty,
		"EVPN type-2 prefix: [2]:[EthTag]:[MAClen]:[MAC]:[IPlen]:[IP]\n");
	vty_out(vty, "EVPN type-3 prefix: [3]:[EthTag]:[IPlen]:[OrigIP]\n");
	vty_out(vty, "EVPN type-4 prefix: [4]:[ESI]:[IPlen]:[OrigIP]\n");
	vty_out(vty, "EVPN type-5 prefix: [5]:[EthTag]:[IPlen]:[IP]\n\n");
	vty_out(vty, "%s", ri_header);
}

static void display_l3vni(struct vty *vty, struct bgp *bgp_vrf,
			  json_object *json)
{
	char buf1[INET6_ADDRSTRLEN];
	char *ecom_str;
	struct listnode *node, *nnode;
	struct ecommunity *ecom;
	json_object *json_import_rtl = NULL;
	json_object *json_export_rtl = NULL;

	json_import_rtl = json_export_rtl = 0;

	if (json) {
		json_import_rtl = json_object_new_array();
		json_export_rtl = json_object_new_array();
		json_object_int_add(json, "vni", bgp_vrf->l3vni);
		json_object_string_add(json, "type", "L3");
		json_object_string_add(json, "kernelFlag", "Yes");
		json_object_string_add(
			json, "rd",
			prefix_rd2str(&bgp_vrf->vrf_prd, buf1, RD_ADDRSTRLEN));
		json_object_string_add(json, "originatorIp",
				       inet_ntoa(bgp_vrf->originator_ip));
		json_object_string_add(json, "advertiseGatewayMacip", "n/a");
		json_object_string_add(json, "advertiseSviMacip", "n/a");
		json_object_to_json_string_ext(json,
					       JSON_C_TO_STRING_NOSLASHESCAPE);
	} else {
		vty_out(vty, "VNI: %d", bgp_vrf->l3vni);
		vty_out(vty, " (known to the kernel)");
		vty_out(vty, "\n");

		vty_out(vty, "  Type: %s\n", "L3");
		vty_out(vty, "  Tenant VRF: %s\n",
			vrf_id_to_name(bgp_vrf->vrf_id));
		vty_out(vty, "  RD: %s\n",
			prefix_rd2str(&bgp_vrf->vrf_prd, buf1, RD_ADDRSTRLEN));
		vty_out(vty, "  Originator IP: %s\n",
			inet_ntoa(bgp_vrf->originator_ip));
		vty_out(vty, "  Advertise-gw-macip : %s\n", "n/a");
		vty_out(vty, "  Advertise-svi-macip : %s\n", "n/a");
	}

	if (!json)
		vty_out(vty, "  Import Route Target:\n");

	for (ALL_LIST_ELEMENTS(bgp_vrf->vrf_import_rtl, node, nnode, ecom)) {
		ecom_str = ecommunity_ecom2str(ecom,
					       ECOMMUNITY_FORMAT_ROUTE_MAP, 0);

		if (json)
			json_object_array_add(json_import_rtl,
					      json_object_new_string(ecom_str));
		else
			vty_out(vty, "    %s\n", ecom_str);

		XFREE(MTYPE_ECOMMUNITY_STR, ecom_str);
	}

	if (json)
		json_object_object_add(json, "importRts", json_import_rtl);
	else
		vty_out(vty, "  Export Route Target:\n");

	for (ALL_LIST_ELEMENTS(bgp_vrf->vrf_export_rtl, node, nnode, ecom)) {
		ecom_str = ecommunity_ecom2str(ecom,
					       ECOMMUNITY_FORMAT_ROUTE_MAP, 0);

		if (json)
			json_object_array_add(json_export_rtl,
					      json_object_new_string(ecom_str));
		else
			vty_out(vty, "    %s\n", ecom_str);

		XFREE(MTYPE_ECOMMUNITY_STR, ecom_str);
	}

	if (json)
		json_object_object_add(json, "exportRts", json_export_rtl);
}

static void display_es(struct vty *vty, struct evpnes *es, json_object *json)
{
	struct in_addr *vtep;
	char buf[ESI_STR_LEN];
	char buf1[RD_ADDRSTRLEN];
	char buf2[INET6_ADDRSTRLEN];
	struct listnode *node = NULL;
	json_object *json_vteps = NULL;

	if (json) {
		json_vteps = json_object_new_array();
		json_object_string_add(json, "esi",
				       esi_to_str(&es->esi, buf, sizeof(buf)));
		json_object_string_add(json, "rd",
				       prefix_rd2str(&es->prd, buf1,
						     sizeof(buf1)));
		json_object_string_add(
			json, "originatorIp",
			ipaddr2str(&es->originator_ip, buf2, sizeof(buf2)));
		if (es->vtep_list) {
			for (ALL_LIST_ELEMENTS_RO(es->vtep_list, node, vtep))
				json_object_array_add(
					json_vteps, json_object_new_string(
							    inet_ntoa(*vtep)));
		}
		json_object_object_add(json, "vteps", json_vteps);
	} else {
		vty_out(vty, "ESI: %s\n",
			esi_to_str(&es->esi, buf, sizeof(buf)));
		vty_out(vty, "  RD: %s\n", prefix_rd2str(&es->prd, buf1,
						       sizeof(buf1)));
		vty_out(vty, "  Originator-IP: %s\n",
			ipaddr2str(&es->originator_ip, buf2, sizeof(buf2)));
		if (es->vtep_list) {
			vty_out(vty, "  VTEP List:\n");
			for (ALL_LIST_ELEMENTS_RO(es->vtep_list, node, vtep))
				vty_out(vty, "    %s\n", inet_ntoa(*vtep));
		}
	}
}

static void display_vni(struct vty *vty, struct bgpevpn *vpn, json_object *json)
{
	char buf1[RD_ADDRSTRLEN];
	char *ecom_str;
	struct listnode *node, *nnode;
	struct ecommunity *ecom;
	json_object *json_import_rtl = NULL;
	json_object *json_export_rtl = NULL;
	struct bgp *bgp_evpn;

	bgp_evpn = bgp_get_evpn();

	if (json) {
		json_import_rtl = json_object_new_array();
		json_export_rtl = json_object_new_array();
		json_object_int_add(json, "vni", vpn->vni);
		json_object_string_add(json, "type", "L2");
		json_object_string_add(json, "kernelFlag",
				       is_vni_live(vpn) ? "Yes" : "No");
		json_object_string_add(
			json, "rd",
			prefix_rd2str(&vpn->prd, buf1, sizeof(buf1)));
		json_object_string_add(json, "originatorIp",
				       inet_ntoa(vpn->originator_ip));
		json_object_string_add(json, "mcastGroup",
				inet_ntoa(vpn->mcast_grp));
		/* per vni knob is enabled -- Enabled
		 * Global knob is enabled  -- Active
		 * default  -- Disabled
		 */
		if (!vpn->advertise_gw_macip &&
		    bgp_evpn && bgp_evpn->advertise_gw_macip)
			json_object_string_add(json, "advertiseGatewayMacip",
					       "Active");
		else if (vpn->advertise_gw_macip)
			json_object_string_add(json, "advertiseGatewayMacip",
					       "Enabled");
		else
			json_object_string_add(json, "advertiseGatewayMacip",
					       "Disabled");
		if (!vpn->advertise_svi_macip && bgp_evpn &&
		    bgp_evpn->evpn_info->advertise_svi_macip)
			json_object_string_add(json, "advertiseSviMacip",
					       "Active");
		else if (vpn->advertise_svi_macip)
			json_object_string_add(json, "advertiseSviMacip",
					       "Enabled");
		else
			json_object_string_add(json, "advertiseSviMacip",
					       "Disabled");
	} else {
		vty_out(vty, "VNI: %d", vpn->vni);
		if (is_vni_live(vpn))
			vty_out(vty, " (known to the kernel)");
		vty_out(vty, "\n");

		vty_out(vty, "  Type: %s\n", "L2");
		vty_out(vty, "  Tenant-Vrf: %s\n",
			vrf_id_to_name(vpn->tenant_vrf_id));
		vty_out(vty, "  RD: %s\n",
			prefix_rd2str(&vpn->prd, buf1, sizeof(buf1)));
		vty_out(vty, "  Originator IP: %s\n",
			inet_ntoa(vpn->originator_ip));
		vty_out(vty, "  Mcast group: %s\n",
				inet_ntoa(vpn->mcast_grp));
		if (!vpn->advertise_gw_macip &&
		    bgp_evpn && bgp_evpn->advertise_gw_macip)
			vty_out(vty, "  Advertise-gw-macip : %s\n",
				"Active");
		else if (vpn->advertise_gw_macip)
			vty_out(vty, "  Advertise-gw-macip : %s\n",
				"Enabled");
		else
			vty_out(vty, "  Advertise-gw-macip : %s\n",
				"Disabled");
		if (!vpn->advertise_svi_macip && bgp_evpn &&
		    bgp_evpn->evpn_info->advertise_svi_macip)
			vty_out(vty, "  Advertise-svi-macip : %s\n",
				"Active");
		else if (vpn->advertise_svi_macip)
			vty_out(vty, "  Advertise-svi-macip : %s\n",
				"Enabled");
		else
			vty_out(vty, "  Advertise-svi-macip : %s\n",
				"Disabled");
	}

	if (!json)
		vty_out(vty, "  Import Route Target:\n");

	for (ALL_LIST_ELEMENTS(vpn->import_rtl, node, nnode, ecom)) {
		ecom_str = ecommunity_ecom2str(ecom,
					       ECOMMUNITY_FORMAT_ROUTE_MAP, 0);

		if (json)
			json_object_array_add(json_import_rtl,
					      json_object_new_string(ecom_str));
		else
			vty_out(vty, "    %s\n", ecom_str);

		XFREE(MTYPE_ECOMMUNITY_STR, ecom_str);
	}

	if (json)
		json_object_object_add(json, "importRts", json_import_rtl);
	else
		vty_out(vty, "  Export Route Target:\n");

	for (ALL_LIST_ELEMENTS(vpn->export_rtl, node, nnode, ecom)) {
		ecom_str = ecommunity_ecom2str(ecom,
					       ECOMMUNITY_FORMAT_ROUTE_MAP, 0);

		if (json)
			json_object_array_add(json_export_rtl,
					      json_object_new_string(ecom_str));
		else
			vty_out(vty, "    %s\n", ecom_str);

		XFREE(MTYPE_ECOMMUNITY_STR, ecom_str);
	}

	if (json)
		json_object_object_add(json, "exportRts", json_export_rtl);
}

static void show_esi_routes(struct bgp *bgp,
			    struct evpnes *es,
			    struct vty *vty,
			    json_object *json)
{
	int header = 1;
	struct bgp_node *rn;
	struct bgp_path_info *pi;
	uint32_t prefix_cnt, path_cnt;
	uint64_t tbl_ver;

	prefix_cnt = path_cnt = 0;

	tbl_ver = es->route_table->version;
	for (rn = bgp_table_top(es->route_table); rn;
	     rn = bgp_route_next(rn)) {
		int add_prefix_to_json = 0;
		char prefix_str[BUFSIZ];
		json_object *json_paths = NULL;
		json_object *json_prefix = NULL;

		bgp_evpn_route2str((struct prefix_evpn *)&rn->p, prefix_str,
				   sizeof(prefix_str));

		if (json)
			json_prefix = json_object_new_object();

		pi = bgp_node_get_bgp_path_info(rn);
		if (pi) {
			/* Overall header/legend displayed once. */
			if (header) {
				bgp_evpn_show_route_header(vty, bgp,
							   tbl_ver, json);
				header = 0;
			}

			prefix_cnt++;
		}

		if (json)
			json_paths = json_object_new_array();

		/* For EVPN, the prefix is displayed for each path (to fit in
		 * with code that already exists).
		 */
		for (; pi; pi = pi->next) {
			json_object *json_path = NULL;

			if (json)
				json_path = json_object_new_array();

			route_vty_out(vty, &rn->p, pi, 0, SAFI_EVPN, json_path);

			if (json)
				json_object_array_add(json_paths, json_path);

			path_cnt++;
			add_prefix_to_json = 1;
		}

		if (json && add_prefix_to_json) {
			json_object_string_add(json_prefix, "prefix",
					       prefix_str);
			json_object_int_add(json_prefix, "prefixLen",
					    rn->p.prefixlen);
			json_object_object_add(json_prefix, "paths",
					       json_paths);
			json_object_object_add(json, prefix_str, json_prefix);
		}
	}

	if (json) {
		json_object_int_add(json, "numPrefix", prefix_cnt);
		json_object_int_add(json, "numPaths", path_cnt);
	} else {
		if (prefix_cnt == 0)
			vty_out(vty, "No EVPN prefixes exist for this ESI\n");
		else
			vty_out(vty, "\nDisplayed %u prefixes (%u paths)\n",
				prefix_cnt, path_cnt);
	}
}

static void show_vni_routes(struct bgp *bgp, struct bgpevpn *vpn, int type,
			    struct vty *vty, struct in_addr vtep_ip,
			    json_object *json, int detail)
{
	struct bgp_node *rn;
	struct bgp_path_info *pi;
	struct bgp_table *table;
	int header = detail ? 0 : 1;
	uint64_t tbl_ver;
	uint32_t prefix_cnt, path_cnt;

	prefix_cnt = path_cnt = 0;

	table = vpn->route_table;
	tbl_ver = table->version;
	for (rn = bgp_table_top(table); rn;
	     rn = bgp_route_next(rn)) {
		struct prefix_evpn *evp = (struct prefix_evpn *)&rn->p;
		int add_prefix_to_json = 0;
		char prefix_str[BUFSIZ];
		json_object *json_paths = NULL;
		json_object *json_prefix = NULL;

		bgp_evpn_route2str((struct prefix_evpn *)&rn->p, prefix_str,
				   sizeof(prefix_str));

		if (type && evp->prefix.route_type != type)
			continue;

		if (json)
			json_prefix = json_object_new_object();

		pi = bgp_node_get_bgp_path_info(rn);
		if (pi) {
			/* Overall header/legend displayed once. */
			if (header) {
				bgp_evpn_show_route_header(vty, bgp,
							   tbl_ver, json);
				header = 0;
			}

			prefix_cnt++;
		}

		if (json)
			json_paths = json_object_new_array();

		/* For EVPN, the prefix is displayed for each path (to fit in
		 * with code that already exists).
		 */
		for (; pi; pi = pi->next) {
			json_object *json_path = NULL;

			if (vtep_ip.s_addr
			    && !IPV4_ADDR_SAME(&(vtep_ip),
					       &(pi->attr->nexthop)))
				continue;

			if (json)
				json_path = json_object_new_array();

			if (detail)
				route_vty_out_detail(vty, bgp, rn, pi,
						     AFI_L2VPN, SAFI_EVPN,
						     json_path);
			else
				route_vty_out(vty, &rn->p, pi, 0, SAFI_EVPN,
					      json_path);

			if (json)
				json_object_array_add(json_paths, json_path);

			path_cnt++;
			add_prefix_to_json = 1;
		}

		if (json && add_prefix_to_json) {
			json_object_string_add(json_prefix, "prefix",
					       prefix_str);
			json_object_int_add(json_prefix, "prefixLen",
					    rn->p.prefixlen);
			json_object_object_add(json_prefix, "paths",
					       json_paths);
			json_object_object_add(json, prefix_str, json_prefix);
		}
	}

	if (json) {
		json_object_int_add(json, "numPrefix", prefix_cnt);
		json_object_int_add(json, "numPaths", path_cnt);
	} else {
		if (prefix_cnt == 0)
			vty_out(vty, "No EVPN prefixes %sexist for this VNI",
				type ? "(of requested type) " : "");
		else
			vty_out(vty, "\nDisplayed %u prefixes (%u paths)%s\n",
				prefix_cnt, path_cnt,
				type ? " (of requested type)" : "");
		vty_out(vty, "\n");
	}
}

static void show_vni_routes_hash(struct hash_bucket *bucket, void *arg)
{
	struct bgpevpn *vpn = (struct bgpevpn *)bucket->data;
	struct vni_walk_ctx *wctx = arg;
	struct vty *vty = wctx->vty;
	json_object *json = wctx->json;
	json_object *json_vni = NULL;
	char vni_str[VNI_STR_LEN];

	snprintf(vni_str, VNI_STR_LEN, "%d", vpn->vni);
	if (json) {
		json_vni = json_object_new_object();
		json_object_int_add(json_vni, "vni", vpn->vni);
	} else {
		vty_out(vty, "\nVNI: %d\n\n", vpn->vni);
	}

	show_vni_routes(wctx->bgp, vpn, 0, wctx->vty, wctx->vtep_ip, json_vni,
			wctx->detail);

	if (json)
		json_object_object_add(json, vni_str, json_vni);
}

static void show_l3vni_entry(struct vty *vty, struct bgp *bgp,
			     json_object *json)
{
	json_object *json_vni = NULL;
	json_object *json_import_rtl = NULL;
	json_object *json_export_rtl = NULL;
	char buf1[10];
	char buf2[INET6_ADDRSTRLEN];
	char rt_buf[25];
	char *ecom_str;
	struct listnode *node, *nnode;
	struct ecommunity *ecom;

	if (!bgp->l3vni)
		return;

	if (json) {
		json_vni = json_object_new_object();
		json_import_rtl = json_object_new_array();
		json_export_rtl = json_object_new_array();
	}

	/* if an l3vni is present in bgp it is live */
	buf1[0] = '\0';
	sprintf(buf1, "*");

	if (json) {
		json_object_int_add(json_vni, "vni", bgp->l3vni);
		json_object_string_add(json_vni, "type", "L3");
		json_object_string_add(json_vni, "inKernel", "True");
		json_object_string_add(json_vni, "originatorIp",
				       inet_ntoa(bgp->originator_ip));
		json_object_string_add(
			json_vni, "rd",
			prefix_rd2str(&bgp->vrf_prd, buf2, RD_ADDRSTRLEN));
	} else {
		vty_out(vty, "%-1s %-10u %-4s %-21s", buf1, bgp->l3vni, "L3",
			prefix_rd2str(&bgp->vrf_prd, buf2, RD_ADDRSTRLEN));
	}

	for (ALL_LIST_ELEMENTS(bgp->vrf_import_rtl, node, nnode, ecom)) {
		ecom_str = ecommunity_ecom2str(ecom,
					       ECOMMUNITY_FORMAT_ROUTE_MAP, 0);

		if (json) {
			json_object_array_add(json_import_rtl,
					      json_object_new_string(ecom_str));
		} else {
			if (listcount(bgp->vrf_import_rtl) > 1)
				sprintf(rt_buf, "%s, ...", ecom_str);
			else
				sprintf(rt_buf, "%s", ecom_str);
			vty_out(vty, " %-25s", rt_buf);
		}

		XFREE(MTYPE_ECOMMUNITY_STR, ecom_str);

		/* If there are multiple import RTs we break here and show only
		 * one */
		if (!json)
			break;
	}

	if (json)
		json_object_object_add(json_vni, "importRTs", json_import_rtl);

	for (ALL_LIST_ELEMENTS(bgp->vrf_export_rtl, node, nnode, ecom)) {
		ecom_str = ecommunity_ecom2str(ecom,
					       ECOMMUNITY_FORMAT_ROUTE_MAP, 0);

		if (json) {
			json_object_array_add(json_export_rtl,
					      json_object_new_string(ecom_str));
		} else {
			if (listcount(bgp->vrf_export_rtl) > 1)
				sprintf(rt_buf, "%s, ...", ecom_str);
			else
				sprintf(rt_buf, "%s", ecom_str);
			vty_out(vty, " %-25s", rt_buf);
		}

		XFREE(MTYPE_ECOMMUNITY_STR, ecom_str);

		/* If there are multiple export RTs we break here and show only
		 * one */
		if (!json)
			break;
	}

	if (!json)
		vty_out(vty, "%-37s", vrf_id_to_name(bgp->vrf_id));

	if (json) {
		char vni_str[VNI_STR_LEN];

		json_object_object_add(json_vni, "exportRTs", json_export_rtl);
		snprintf(vni_str, VNI_STR_LEN, "%u", bgp->l3vni);
		json_object_object_add(json, vni_str, json_vni);
	} else {
		vty_out(vty, "\n");
	}
}

static void show_es_entry(struct hash_bucket *bucket, void *args[])
{
	char buf[ESI_STR_LEN];
	char buf1[RD_ADDRSTRLEN];
	char buf2[INET6_ADDRSTRLEN];
	struct in_addr *vtep = NULL;
	struct vty *vty = args[0];
	json_object *json = args[1];
	json_object *json_vteps = NULL;
	struct listnode *node = NULL;
	struct evpnes *es = (struct evpnes *)bucket->data;

	if (json) {
		json_vteps = json_object_new_array();
		json_object_string_add(json, "esi",
				       esi_to_str(&es->esi, buf, sizeof(buf)));
		json_object_string_add(json, "type",
				       is_es_local(es) ? "Local" : "Remote");
		json_object_string_add(json, "rd",
				       prefix_rd2str(&es->prd, buf1,
						     sizeof(buf1)));
		json_object_string_add(
			json, "originatorIp",
			ipaddr2str(&es->originator_ip, buf2, sizeof(buf2)));
		if (es->vtep_list) {
			for (ALL_LIST_ELEMENTS_RO(es->vtep_list, node, vtep))
				json_object_array_add(json_vteps,
						json_object_new_string(
							inet_ntoa(*vtep)));
		}
		json_object_object_add(json, "vteps", json_vteps);
	} else {
		vty_out(vty, "%-30s %-6s %-21s %-15s %-6d\n",
			esi_to_str(&es->esi, buf, sizeof(buf)),
			is_es_local(es) ? "Local" : "Remote",
			prefix_rd2str(&es->prd, buf1, sizeof(buf1)),
			ipaddr2str(&es->originator_ip, buf2,
				   sizeof(buf2)),
			es->vtep_list ? listcount(es->vtep_list) : 0);
	}
}

static void show_vni_entry(struct hash_bucket *bucket, void *args[])
{
	struct vty *vty;
	json_object *json;
	json_object *json_vni = NULL;
	json_object *json_import_rtl = NULL;
	json_object *json_export_rtl = NULL;
	struct bgpevpn *vpn = (struct bgpevpn *)bucket->data;
	char buf1[10];
	char buf2[RD_ADDRSTRLEN];
	char rt_buf[25];
	char *ecom_str;
	struct listnode *node, *nnode;
	struct ecommunity *ecom;

	vty = args[0];
	json = args[1];

	if (json) {
		json_vni = json_object_new_object();
		json_import_rtl = json_object_new_array();
		json_export_rtl = json_object_new_array();
	}

	buf1[0] = '\0';
	if (is_vni_live(vpn))
		sprintf(buf1, "*");

	if (json) {
		json_object_int_add(json_vni, "vni", vpn->vni);
		json_object_string_add(json_vni, "type", "L2");
		json_object_string_add(json_vni, "inKernel",
				       is_vni_live(vpn) ? "True" : "False");
		json_object_string_add(json_vni, "originatorIp",
				       inet_ntoa(vpn->originator_ip));
		json_object_string_add(json_vni, "originatorIp",
				       inet_ntoa(vpn->originator_ip));
		json_object_string_add(
			json_vni, "rd",
			prefix_rd2str(&vpn->prd, buf2, sizeof(buf2)));
	} else {
		vty_out(vty, "%-1s %-10u %-4s %-21s", buf1, vpn->vni, "L2",
			prefix_rd2str(&vpn->prd, buf2, RD_ADDRSTRLEN));
	}

	for (ALL_LIST_ELEMENTS(vpn->import_rtl, node, nnode, ecom)) {
		ecom_str = ecommunity_ecom2str(ecom,
					       ECOMMUNITY_FORMAT_ROUTE_MAP, 0);

		if (json) {
			json_object_array_add(json_import_rtl,
					      json_object_new_string(ecom_str));
		} else {
			if (listcount(vpn->import_rtl) > 1)
				sprintf(rt_buf, "%s, ...", ecom_str);
			else
				sprintf(rt_buf, "%s", ecom_str);
			vty_out(vty, " %-25s", rt_buf);
		}

		XFREE(MTYPE_ECOMMUNITY_STR, ecom_str);

		/* If there are multiple import RTs we break here and show only
		 * one */
		if (!json)
			break;
	}

	if (json)
		json_object_object_add(json_vni, "importRTs", json_import_rtl);

	for (ALL_LIST_ELEMENTS(vpn->export_rtl, node, nnode, ecom)) {
		ecom_str = ecommunity_ecom2str(ecom,
					       ECOMMUNITY_FORMAT_ROUTE_MAP, 0);

		if (json) {
			json_object_array_add(json_export_rtl,
					      json_object_new_string(ecom_str));
		} else {
			if (listcount(vpn->export_rtl) > 1)
				sprintf(rt_buf, "%s, ...", ecom_str);
			else
				sprintf(rt_buf, "%s", ecom_str);
			vty_out(vty, " %-25s", rt_buf);
		}

		XFREE(MTYPE_ECOMMUNITY_STR, ecom_str);

		/* If there are multiple export RTs we break here and show only
		 * one */
		if (!json)
			break;
	}

	if (!json)
		vty_out(vty, "%-37s", vrf_id_to_name(vpn->tenant_vrf_id));

	if (json) {
		char vni_str[VNI_STR_LEN];

		json_object_object_add(json_vni, "exportRTs", json_export_rtl);
		snprintf(vni_str, VNI_STR_LEN, "%u", vpn->vni);
		json_object_object_add(json, vni_str, json_vni);
	} else {
		vty_out(vty, "\n");
	}
}

static int bgp_show_ethernet_vpn(struct vty *vty, struct prefix_rd *prd,
				 enum bgp_show_type type, void *output_arg,
				 int option, bool use_json)
{
	afi_t afi = AFI_L2VPN;
	struct bgp *bgp;
	struct bgp_table *table;
	struct bgp_node *rn;
	struct bgp_node *rm;
	struct bgp_path_info *pi;
	int rd_header;
	int header = 1;
	char rd_str[RD_ADDRSTRLEN];
	char buf[BUFSIZ];
	int no_display;

	unsigned long output_count = 0;
	unsigned long total_count = 0;
	json_object *json = NULL;
	json_object *json_array = NULL;
	json_object *json_prefix_info = NULL;

	memset(rd_str, 0, RD_ADDRSTRLEN);

	bgp = bgp_get_evpn();
	if (bgp == NULL) {
		if (!use_json)
			vty_out(vty, "No BGP process is configured\n");
		else
			vty_out(vty, "{}\n");
		return CMD_WARNING;
	}

	if (use_json)
		json = json_object_new_object();

	for (rn = bgp_table_top(bgp->rib[afi][SAFI_EVPN]); rn;
	     rn = bgp_route_next(rn)) {
		uint64_t tbl_ver;
		json_object *json_nroute = NULL;

		if (prd && memcmp(rn->p.u.val, prd->val, 8) != 0)
			continue;

		table = bgp_node_get_bgp_table_info(rn);
		if (!table)
			continue;

		rd_header = 1;
		tbl_ver = table->version;

		for (rm = bgp_table_top(table); rm; rm = bgp_route_next(rm)) {
			pi = bgp_node_get_bgp_path_info(rm);
			if (pi == NULL)
				continue;

			no_display = 0;
			for (; pi; pi = pi->next) {
				total_count++;
				if (type == bgp_show_type_neighbor) {
				        struct peer *peer = output_arg;

					if (peer_cmp(peer, pi->peer) != 0)
						continue;
				}
				if (type == bgp_show_type_lcommunity_exact) {
					struct lcommunity *lcom = output_arg;

					if (!pi->attr->lcommunity ||
						!lcommunity_cmp(
						pi->attr->lcommunity, lcom))
						continue;
				}
				if (type == bgp_show_type_lcommunity) {
					struct lcommunity *lcom = output_arg;

					if (!pi->attr->lcommunity ||
						!lcommunity_match(
						pi->attr->lcommunity, lcom))
						continue;
				}
				if (type == bgp_show_type_community) {
					struct community *com = output_arg;

					if (!pi->attr->community ||
						!community_match(
						pi->attr->community, com))
						continue;
				}
				if (type == bgp_show_type_community_exact) {
					struct community *com = output_arg;

					if (!pi->attr->community ||
						!community_cmp(
						pi->attr->community, com))
						continue;
				}
				if (header) {
					if (use_json) {
						json_object_int_add(
							json, "bgpTableVersion",
							tbl_ver);
						json_object_string_add(
							json,
							"bgpLocalRouterId",
							inet_ntoa(
							bgp->router_id));
						json_object_int_add(
							json,
							"defaultLocPrf",
							bgp->default_local_pref);
						json_object_int_add(
							json, "localAS",
							bgp->as);
					} else {
						if (option == SHOW_DISPLAY_TAGS)
							vty_out(vty,
								V4_HEADER_TAG);
						else if (
							option
							== SHOW_DISPLAY_OVERLAY)
							vty_out(vty,
								V4_HEADER_OVERLAY);
						else {
							bgp_evpn_show_route_header(vty, bgp, tbl_ver, NULL);
						}
					}
					header = 0;
				}
				if (rd_header) {
					if (use_json)
						json_nroute =
						       json_object_new_object();
					bgp_evpn_show_route_rd_header(vty, rn,
						json_nroute, rd_str,
						RD_ADDRSTRLEN);
					rd_header = 0;
				}
				if (use_json && !json_array)
					json_array = json_object_new_array();

				if (option == SHOW_DISPLAY_TAGS)
					route_vty_out_tag(vty, &rm->p, pi,
							  no_display, SAFI_EVPN,
							  json_array);
				else if (option == SHOW_DISPLAY_OVERLAY)
					route_vty_out_overlay(vty, &rm->p, pi,
							      no_display,
							      json_array);
				else
					route_vty_out(vty, &rm->p, pi,
						      no_display, SAFI_EVPN,
						      json_array);
				no_display = 1;
			}

			if (no_display)
				output_count++;

			if (use_json && json_array) {
				json_prefix_info = json_object_new_object();

				json_object_string_add(json_prefix_info,
					"prefix", bgp_evpn_route2str(
					(struct prefix_evpn *)&rm->p, buf,
					BUFSIZ));

				json_object_int_add(json_prefix_info,
					"prefixLen", rm->p.prefixlen);

				json_object_object_add(json_prefix_info,
					"paths", json_array);
				json_object_object_add(json_nroute, buf,
					json_prefix_info);
				json_array = NULL;
			}
		}

		if (use_json && json_nroute)
			json_object_object_add(json, rd_str, json_nroute);
	}

	if (use_json) {
		json_object_int_add(json, "numPrefix", output_count);
		json_object_int_add(json, "totalPrefix", total_count);
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
			json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	} else {
		if (output_count == 0)
			vty_out(vty, "No prefixes displayed, %ld exist\n",
				total_count);
		else
			vty_out(vty,
				"\nDisplayed %ld out of %ld total prefixes\n",
				output_count, total_count);
	}
	return CMD_SUCCESS;
}

DEFUN(show_ip_bgp_l2vpn_evpn,
      show_ip_bgp_l2vpn_evpn_cmd,
      "show [ip] bgp l2vpn evpn [json]",
      SHOW_STR IP_STR BGP_STR L2VPN_HELP_STR EVPN_HELP_STR JSON_STR)
{
	return bgp_show_ethernet_vpn(vty, NULL, bgp_show_type_normal, NULL, 0,
				     use_json(argc, argv));
}

DEFUN(show_ip_bgp_l2vpn_evpn_rd,
      show_ip_bgp_l2vpn_evpn_rd_cmd,
      "show [ip] bgp l2vpn evpn rd ASN:NN_OR_IP-ADDRESS:NN [json]",
      SHOW_STR
      IP_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "Display information for a route distinguisher\n"
      "VPN Route Distinguisher\n" JSON_STR)
{
	int idx_ext_community = 0;
	int ret;
	struct prefix_rd prd;

	argv_find(argv, argc, "ASN:NN_OR_IP-ADDRESS:NN", &idx_ext_community);

	ret = str2prefix_rd(argv[idx_ext_community]->arg, &prd);
	if (!ret) {
		vty_out(vty, "%% Malformed Route Distinguisher\n");
		return CMD_WARNING;
	}
	return bgp_show_ethernet_vpn(vty, &prd, bgp_show_type_normal, NULL, 0,
				     use_json(argc, argv));
}

DEFUN(show_ip_bgp_l2vpn_evpn_all_tags,
      show_ip_bgp_l2vpn_evpn_all_tags_cmd,
      "show [ip] bgp l2vpn evpn all tags",
      SHOW_STR
      IP_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "Display information about all EVPN NLRIs\n"
      "Display BGP tags for prefixes\n")
{
	return bgp_show_ethernet_vpn(vty, NULL, bgp_show_type_normal, NULL, 1,
				     0);
}

DEFUN(show_ip_bgp_l2vpn_evpn_rd_tags,
      show_ip_bgp_l2vpn_evpn_rd_tags_cmd,
      "show [ip] bgp l2vpn evpn rd ASN:NN_OR_IP-ADDRESS:NN tags",
      SHOW_STR
      IP_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "Display information for a route distinguisher\n"
      "VPN Route Distinguisher\n" "Display BGP tags for prefixes\n")
{
	int idx_ext_community = 0;
	int ret;
	struct prefix_rd prd;

	argv_find(argv, argc, "ASN:NN_OR_IP-ADDRESS:NN", &idx_ext_community);

	ret = str2prefix_rd(argv[idx_ext_community]->arg, &prd);
	if (!ret) {
		vty_out(vty, "%% Malformed Route Distinguisher\n");
		return CMD_WARNING;
	}
	return bgp_show_ethernet_vpn(vty, &prd, bgp_show_type_normal, NULL, 1,
				     0);
}

DEFUN(show_ip_bgp_l2vpn_evpn_neighbor_routes,
      show_ip_bgp_l2vpn_evpn_neighbor_routes_cmd,
      "show [ip] bgp l2vpn evpn neighbors <A.B.C.D|X:X::X:X|WORD> routes [json]",
      SHOW_STR
      IP_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "Detailed information on TCP and BGP neighbor connections\n"
      "IPv4 Neighbor to display information about\n"
      "IPv6 Neighbor to display information about\n"
      "Neighbor on BGP configured interface\n"
      "Display routes learned from neighbor\n" JSON_STR)
{
	int idx = 0;
	struct peer *peer;
	char *peerstr = NULL;
	bool uj = use_json(argc, argv);
	afi_t afi = AFI_L2VPN;
	safi_t safi = SAFI_EVPN;
	struct bgp *bgp = NULL;

	bgp_vty_find_and_parse_afi_safi_bgp(vty, argv, argc, &idx, &afi, &safi,
					    &bgp, uj);
	if (!idx) {
	        vty_out(vty, "No index\n");
		return CMD_WARNING;
	}

	/* neighbors <A.B.C.D|X:X::X:X|WORD> */
	argv_find(argv, argc, "neighbors", &idx);
	peerstr = argv[++idx]->arg;

	peer = peer_lookup_in_view(vty, bgp, peerstr, uj);
	if (!peer) {
		if (uj) {
			json_object *json_no = NULL;
			json_no = json_object_new_object();
			json_object_string_add(json_no, "warning",
					       "Malformed address");
			vty_out(vty, "%s\n",
				json_object_to_json_string(json_no));
			json_object_free(json_no);
		} else
			vty_out(vty, "Malformed address: %s\n",
				argv[idx]->arg);
		return CMD_WARNING;
	}
	if (!peer || !peer->afc[AFI_L2VPN][SAFI_EVPN]) {
		if (uj) {
			json_object *json_no = NULL;
			json_no = json_object_new_object();
			json_object_string_add(
				json_no, "warning",
				"No such neighbor or address family");
			vty_out(vty, "%s\n",
				json_object_to_json_string(json_no));
			json_object_free(json_no);
		} else
			vty_out(vty, "%% No such neighbor or address family\n");
		return CMD_WARNING;
	}

	return bgp_show_ethernet_vpn(vty, NULL, bgp_show_type_neighbor, peer, 0,
				     uj);
}

DEFUN(show_ip_bgp_l2vpn_evpn_rd_neighbor_routes,
      show_ip_bgp_l2vpn_evpn_rd_neighbor_routes_cmd,
      "show [ip] bgp l2vpn evpn rd ASN:NN_OR_IP-ADDRESS:NN neighbors <A.B.C.D|X:X::X:X|WORD> routes [json]",
      SHOW_STR
      IP_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "Display information for a route distinguisher\n"
      "VPN Route Distinguisher\n"
      "Detailed information on TCP and BGP neighbor connections\n"
      "IPv4 Neighbor to display information about\n"
      "IPv6 Neighbor to display information about\n"
      "Neighbor on BGP configured interface\n"
      "Display routes learned from neighbor\n" JSON_STR)
{
	int idx_ext_community = 0;
	int idx = 0;
	int ret;
	struct peer *peer;
	char *peerstr = NULL;
	struct prefix_rd prd;
	bool uj = use_json(argc, argv);
	afi_t afi = AFI_L2VPN;
	safi_t safi = SAFI_EVPN;
	struct bgp *bgp = NULL;

	bgp_vty_find_and_parse_afi_safi_bgp(vty, argv, argc, &idx, &afi, &safi,
					    &bgp, uj);
	if (!idx) {
	        vty_out(vty, "No index\n");
		return CMD_WARNING;
	}

	argv_find(argv, argc, "ASN:NN_OR_IP-ADDRESS:NN", &idx_ext_community);
	ret = str2prefix_rd(argv[idx_ext_community]->arg, &prd);
	if (!ret) {
		if (uj) {
			json_object *json_no = NULL;
			json_no = json_object_new_object();
			json_object_string_add(json_no, "warning",
					       "Malformed Route Distinguisher");
			vty_out(vty, "%s\n",
				json_object_to_json_string(json_no));
			json_object_free(json_no);
		} else
			vty_out(vty, "%% Malformed Route Distinguisher\n");
		return CMD_WARNING;
	}

	/* neighbors <A.B.C.D|X:X::X:X|WORD> */
	argv_find(argv, argc, "neighbors", &idx);
	peerstr = argv[++idx]->arg;

	peer = peer_lookup_in_view(vty, bgp, peerstr, uj);
	if (!peer) {
		if (uj) {
			json_object *json_no = NULL;
			json_no = json_object_new_object();
			json_object_string_add(json_no, "warning",
					       "Malformed address");
			vty_out(vty, "%s\n",
				json_object_to_json_string(json_no));
			json_object_free(json_no);
		} else
			vty_out(vty, "Malformed address: %s\n",
				argv[idx]->arg);
		return CMD_WARNING;
	}
	if (!peer || !peer->afc[AFI_L2VPN][SAFI_EVPN]) {
		if (uj) {
			json_object *json_no = NULL;
			json_no = json_object_new_object();
			json_object_string_add(
				json_no, "warning",
				"No such neighbor or address family");
			vty_out(vty, "%s\n",
				json_object_to_json_string(json_no));
			json_object_free(json_no);
		} else
			vty_out(vty, "%% No such neighbor or address family\n");
		return CMD_WARNING;
	}

	return bgp_show_ethernet_vpn(vty, &prd, bgp_show_type_neighbor, peer, 0,
				     uj);
}

DEFUN(show_ip_bgp_l2vpn_evpn_neighbor_advertised_routes,
      show_ip_bgp_l2vpn_evpn_neighbor_advertised_routes_cmd,
      "show [ip] bgp l2vpn evpn neighbors <A.B.C.D|X:X::X:X|WORD> advertised-routes [json]",
      SHOW_STR
      IP_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "Detailed information on TCP and BGP neighbor connections\n"
      "IPv4 Neighbor to display information about\n"
      "IPv6 Neighbor to display information about\n"
      "Neighbor on BGP configured interface\n"
      "Display the routes advertised to a BGP neighbor\n" JSON_STR)
{
	int idx = 0;
	struct peer *peer;
	bool uj = use_json(argc, argv);
	struct bgp *bgp = NULL;
	afi_t afi = AFI_L2VPN;
	safi_t safi = SAFI_EVPN;
	char *peerstr = NULL;

	if (uj)
		argc--;

	bgp_vty_find_and_parse_afi_safi_bgp(vty, argv, argc, &idx, &afi, &safi,
					    &bgp, uj);
	if (!idx) {
	        vty_out(vty, "No index\n");
		return CMD_WARNING;
	}

	/* neighbors <A.B.C.D|X:X::X:X|WORD> */
	argv_find(argv, argc, "neighbors", &idx);
	peerstr = argv[++idx]->arg;

	peer = peer_lookup_in_view(vty, bgp, peerstr, uj);
	if (!peer) {
		if (uj) {
			json_object *json_no = NULL;
			json_no = json_object_new_object();
			json_object_string_add(json_no, "warning",
					       "Malformed address");
			vty_out(vty, "%s\n",
				json_object_to_json_string(json_no));
			json_object_free(json_no);
		} else
			vty_out(vty, "Malformed address: %s\n",
				argv[idx]->arg);
		return CMD_WARNING;
	}
	if (!peer || !peer->afc[AFI_L2VPN][SAFI_EVPN]) {
		if (uj) {
			json_object *json_no = NULL;
			json_no = json_object_new_object();
			json_object_string_add(
				json_no, "warning",
				"No such neighbor or address family");
			vty_out(vty, "%s\n",
				json_object_to_json_string(json_no));
			json_object_free(json_no);
		} else
			vty_out(vty, "%% No such neighbor or address family\n");
		return CMD_WARNING;
	}

	return show_adj_route_vpn(vty, peer, NULL, AFI_L2VPN, SAFI_EVPN, uj);
}

DEFUN(show_ip_bgp_l2vpn_evpn_rd_neighbor_advertised_routes,
      show_ip_bgp_l2vpn_evpn_rd_neighbor_advertised_routes_cmd,
      "show [ip] bgp l2vpn evpn rd ASN:NN_OR_IP-ADDRESS:NN neighbors <A.B.C.D|X:X::X:X|WORD> advertised-routes [json]",
      SHOW_STR
      IP_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "Display information for a route distinguisher\n"
      "VPN Route Distinguisher\n"
      "Detailed information on TCP and BGP neighbor connections\n"
      "IPv4 Neighbor to display information about\n"
      "IPv6 Neighbor to display information about\n"
      "Neighbor on BGP configured interface\n"
      "Display the routes advertised to a BGP neighbor\n" JSON_STR)
{
	int idx_ext_community = 0;
	int idx = 0;
	int ret;
	struct peer *peer;
	struct prefix_rd prd;
	struct bgp *bgp = NULL;
	bool uj = use_json(argc, argv);
	char *peerstr = NULL;
	afi_t afi = AFI_L2VPN;
	safi_t safi = SAFI_EVPN;

	if (uj)
		argc--;

	if (uj)
		argc--;

	bgp_vty_find_and_parse_afi_safi_bgp(vty, argv, argc, &idx, &afi, &safi,
					    &bgp, uj);
	if (!idx) {
	        vty_out(vty, "No index\n");
		return CMD_WARNING;
	}

	argv_find(argv, argc, "ASN:NN_OR_IP-ADDRESS:NN", &idx_ext_community);

	/* neighbors <A.B.C.D|X:X::X:X|WORD> */
	argv_find(argv, argc, "neighbors", &idx);
	peerstr = argv[++idx]->arg;

	peer = peer_lookup_in_view(vty, bgp, peerstr, uj);
	if (!peer) {
		if (uj) {
			json_object *json_no = NULL;
			json_no = json_object_new_object();
			json_object_string_add(json_no, "warning",
					       "Malformed address");
			vty_out(vty, "%s\n",
				json_object_to_json_string(json_no));
			json_object_free(json_no);
		} else
			vty_out(vty, "Malformed address: %s\n",
				argv[idx]->arg);
		return CMD_WARNING;
	}
	if (!peer || !peer->afc[AFI_L2VPN][SAFI_EVPN]) {
		if (uj) {
			json_object *json_no = NULL;
			json_no = json_object_new_object();
			json_object_string_add(
				json_no, "warning",
				"No such neighbor or address family");
			vty_out(vty, "%s\n",
				json_object_to_json_string(json_no));
			json_object_free(json_no);
		} else
			vty_out(vty, "%% No such neighbor or address family\n");
		return CMD_WARNING;
	}

	ret = str2prefix_rd(argv[idx_ext_community]->arg, &prd);
	if (!ret) {
		if (uj) {
			json_object *json_no = NULL;
			json_no = json_object_new_object();
			json_object_string_add(json_no, "warning",
					       "Malformed Route Distinguisher");
			vty_out(vty, "%s\n",
				json_object_to_json_string(json_no));
			json_object_free(json_no);
		} else
			vty_out(vty, "%% Malformed Route Distinguisher\n");
		return CMD_WARNING;
	}

	return show_adj_route_vpn(vty, peer, &prd, AFI_L2VPN, SAFI_EVPN, uj);
}

DEFUN(show_ip_bgp_l2vpn_evpn_all_overlay,
      show_ip_bgp_l2vpn_evpn_all_overlay_cmd,
      "show [ip] bgp l2vpn evpn all overlay [json]",
      SHOW_STR
      IP_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "Display information about all EVPN NLRIs\n"
      "Display BGP Overlay Information for prefixes\n"
      JSON_STR)
{
	return bgp_show_ethernet_vpn(vty, NULL, bgp_show_type_normal, NULL,
				     SHOW_DISPLAY_OVERLAY,
				     use_json(argc, argv));
}

DEFUN(show_ip_bgp_evpn_rd_overlay,
      show_ip_bgp_evpn_rd_overlay_cmd,
      "show [ip] bgp l2vpn evpn rd ASN:NN_OR_IP-ADDRESS:NN overlay",
      SHOW_STR
      IP_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "Display information for a route distinguisher\n"
      "VPN Route Distinguisher\n"
      "Display BGP Overlay Information for prefixes\n")
{
	int idx_ext_community = 0;
	int ret;
	struct prefix_rd prd;

	argv_find(argv, argc, "ASN:NN_OR_IP-ADDRESS:NN", &idx_ext_community);

	ret = str2prefix_rd(argv[idx_ext_community]->arg, &prd);
	if (!ret) {
		vty_out(vty, "%% Malformed Route Distinguisher\n");
		return CMD_WARNING;
	}
	return bgp_show_ethernet_vpn(vty, &prd, bgp_show_type_normal, NULL,
				     SHOW_DISPLAY_OVERLAY,
				     use_json(argc, argv));
}

DEFUN(show_bgp_l2vpn_evpn_com,
      show_bgp_l2vpn_evpn_com_cmd,
      "show bgp l2vpn evpn \
      <community AA:NN|large-community AA:BB:CC> \
      [exact-match] [json]",
      SHOW_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "Display routes matching the community\n"
      "Community number where AA and NN are (0-65535)\n"
      "Display routes matching the large-community\n"
      "List of large-community numbers\n"
      "Exact match of the communities\n"
      JSON_STR)
{
	int idx = 0;
	int ret = 0;
	const char *clist_number_or_name;
	int show_type = bgp_show_type_normal;
	struct community *com;
	struct lcommunity *lcom;

	if (argv_find(argv, argc, "large-community", &idx)) {
		clist_number_or_name = argv[++idx]->arg;
		show_type = bgp_show_type_lcommunity;

		if (++idx < argc && strmatch(argv[idx]->text, "exact-match"))
			show_type = bgp_show_type_lcommunity_exact;

		lcom = lcommunity_str2com(clist_number_or_name);
		if (!lcom) {
			vty_out(vty, "%% Large-community malformed\n");
			return CMD_WARNING;
		}

		ret = bgp_show_ethernet_vpn(vty, NULL, show_type, lcom,
					    SHOW_DISPLAY_STANDARD,
					    use_json(argc, argv));

		lcommunity_free(&lcom);
	} else if (argv_find(argv, argc, "community", &idx)) {
		clist_number_or_name = argv[++idx]->arg;
		show_type = bgp_show_type_community;

		if (++idx < argc && strmatch(argv[idx]->text, "exact-match"))
			show_type = bgp_show_type_community_exact;

		com = community_str2com(clist_number_or_name);

		if (!com) {
			vty_out(vty, "%% Community malformed: %s\n",
				clist_number_or_name);
			return CMD_WARNING;
		}

		ret = bgp_show_ethernet_vpn(vty, NULL, show_type, com,
					    SHOW_DISPLAY_STANDARD,
					    use_json(argc, argv));
		community_free(&com);
	}

	return ret;
}

/* For testing purpose, static route of EVPN RT-5. */
DEFUN(evpnrt5_network,
      evpnrt5_network_cmd,
      "network <A.B.C.D/M|X:X::X:X/M> rd ASN:NN_OR_IP-ADDRESS:NN ethtag WORD label WORD esi WORD gwip <A.B.C.D|X:X::X:X> routermac WORD [route-map WORD]",
      "Specify a network to announce via BGP\n"
      "IP prefix\n"
      "IPv6 prefix\n"
      "Specify Route Distinguisher\n"
      "VPN Route Distinguisher\n"
      "Ethernet Tag\n"
      "Ethernet Tag Value\n"
      "BGP label\n"
      "label value\n"
      "Ethernet Segment Identifier\n"
      "ESI value ( 00:11:22:33:44:55:66:77:88:99 format) \n"
      "Gateway IP\n"
      "Gateway IP ( A.B.C.D )\n"
      "Gateway IPv6 ( X:X::X:X )\n"
      "Router Mac Ext Comm\n"
      "Router Mac address Value ( aa:bb:cc:dd:ee:ff format)\n"
      "Route-map to modify the attributes\n"
      "Name of the route map\n")
{
	int idx_ipv4_prefixlen = 1;
	int idx_route_distinguisher = 3;
	int idx_label = 7;
	int idx_esi = 9;
	int idx_gwip = 11;
	int idx_ethtag = 5;
	int idx_routermac = 13;

	return bgp_static_set_safi(
		AFI_L2VPN, SAFI_EVPN, vty, argv[idx_ipv4_prefixlen]->arg,
		argv[idx_route_distinguisher]->arg, argv[idx_label]->arg, NULL,
		BGP_EVPN_IP_PREFIX_ROUTE, argv[idx_esi]->arg,
		argv[idx_gwip]->arg, argv[idx_ethtag]->arg,
		argv[idx_routermac]->arg);
}

/* For testing purpose, static route of EVPN RT-5. */
DEFUN(no_evpnrt5_network,
      no_evpnrt5_network_cmd,
      "no network <A.B.C.D/M|X:X::X:X/M> rd ASN:NN_OR_IP-ADDRESS:NN ethtag WORD label WORD esi WORD gwip <A.B.C.D|X:X::X:X>",
      NO_STR
      "Specify a network to announce via BGP\n"
      "IP prefix\n"
      "IPv6 prefix\n"
      "Specify Route Distinguisher\n"
      "VPN Route Distinguisher\n"
      "Ethernet Tag\n"
      "Ethernet Tag Value\n"
      "BGP label\n"
      "label value\n"
      "Ethernet Segment Identifier\n"
      "ESI value ( 00:11:22:33:44:55:66:77:88:99 format) \n"
      "Gateway IP\n" "Gateway IP ( A.B.C.D )\n" "Gateway IPv6 ( X:X::X:X )\n")
{
	int idx_ipv4_prefixlen = 2;
	int idx_ext_community = 4;
	int idx_label = 8;
	int idx_ethtag = 6;
	int idx_esi = 10;
	int idx_gwip = 12;
	return bgp_static_unset_safi(
		AFI_L2VPN, SAFI_EVPN, vty, argv[idx_ipv4_prefixlen]->arg,
		argv[idx_ext_community]->arg, argv[idx_label]->arg,
		BGP_EVPN_IP_PREFIX_ROUTE, argv[idx_esi]->arg,
		argv[idx_gwip]->arg, argv[idx_ethtag]->arg);
}

static void evpn_import_rt_delete_auto(struct bgp *bgp, struct bgpevpn *vpn)
{
	evpn_rt_delete_auto(bgp, vpn->vni, vpn->import_rtl);
}

static void evpn_export_rt_delete_auto(struct bgp *bgp, struct bgpevpn *vpn)
{
	evpn_rt_delete_auto(bgp, vpn->vni, vpn->export_rtl);
}

/*
 * Configure the Import RTs for a VNI (vty handler). Caller expected to
 * check that this is a change.
 */
static void evpn_configure_import_rt(struct bgp *bgp, struct bgpevpn *vpn,
				     struct ecommunity *ecomadd)
{
	/* If the VNI is "live", we need to uninstall routes using the current
	 * import RT(s) first before we update the import RT, and subsequently
	 * install routes.
	 */
	if (is_vni_live(vpn))
		bgp_evpn_uninstall_routes(bgp, vpn);

	/* Cleanup the RT to VNI mapping and get rid of existing import RT. */
	bgp_evpn_unmap_vni_from_its_rts(bgp, vpn);

	/* If the auto route-target is in use we must remove it */
	evpn_import_rt_delete_auto(bgp, vpn);

	/* Add new RT and rebuild the RT to VNI mapping */
	listnode_add_sort(vpn->import_rtl, ecomadd);

	SET_FLAG(vpn->flags, VNI_FLAG_IMPRT_CFGD);
	bgp_evpn_map_vni_to_its_rts(bgp, vpn);

	/* Install routes that match new import RT */
	if (is_vni_live(vpn))
		bgp_evpn_install_routes(bgp, vpn);
}

/*
 * Unconfigure Import RT(s) for a VNI (vty handler).
 */
static void evpn_unconfigure_import_rt(struct bgp *bgp, struct bgpevpn *vpn,
				       struct ecommunity *ecomdel)
{
	struct listnode *node, *nnode, *node_to_del;
	struct ecommunity *ecom;

	/* Along the lines of "configure" except we have to reset to the
	 * automatic value.
	 */
	if (is_vni_live(vpn))
		bgp_evpn_uninstall_routes(bgp, vpn);

	/* Cleanup the RT to VNI mapping and get rid of existing import RT. */
	bgp_evpn_unmap_vni_from_its_rts(bgp, vpn);

	/* Delete all import RTs */
	if (ecomdel == NULL) {
		for (ALL_LIST_ELEMENTS(vpn->import_rtl, node, nnode, ecom)) {
			ecommunity_free(&ecom);
			list_delete_node(vpn->import_rtl, node);
		}
	}

	/* Delete a specific import RT */
	else {
		node_to_del = NULL;

		for (ALL_LIST_ELEMENTS(vpn->import_rtl, node, nnode, ecom)) {
			if (ecommunity_match(ecom, ecomdel)) {
				ecommunity_free(&ecom);
				node_to_del = node;
				break;
			}
		}

		if (node_to_del)
			list_delete_node(vpn->import_rtl, node_to_del);
	}

	assert(vpn->import_rtl);
	/* Reset to auto RT - this also rebuilds the RT to VNI mapping */
	if (list_isempty(vpn->import_rtl)) {
		UNSET_FLAG(vpn->flags, VNI_FLAG_IMPRT_CFGD);
		bgp_evpn_derive_auto_rt_import(bgp, vpn);
	}
	/* Rebuild the RT to VNI mapping */
	else
		bgp_evpn_map_vni_to_its_rts(bgp, vpn);

	/* Install routes that match new import RT */
	if (is_vni_live(vpn))
		bgp_evpn_install_routes(bgp, vpn);
}

/*
 * Configure the Export RT for a VNI (vty handler). Caller expected to
 * check that this is a change. Note that only a single export RT is
 * allowed for a VNI and any change to configuration is implemented as
 * a "replace" (similar to other configuration).
 */
static void evpn_configure_export_rt(struct bgp *bgp, struct bgpevpn *vpn,
				     struct ecommunity *ecomadd)
{
	/* If the auto route-target is in use we must remove it */
	evpn_export_rt_delete_auto(bgp, vpn);

	listnode_add_sort(vpn->export_rtl, ecomadd);
	SET_FLAG(vpn->flags, VNI_FLAG_EXPRT_CFGD);

	if (is_vni_live(vpn))
		bgp_evpn_handle_export_rt_change(bgp, vpn);
}

/*
 * Unconfigure the Export RT for a VNI (vty handler)
 */
static void evpn_unconfigure_export_rt(struct bgp *bgp, struct bgpevpn *vpn,
				       struct ecommunity *ecomdel)
{
	struct listnode *node, *nnode, *node_to_del;
	struct ecommunity *ecom;

	/* Delete all export RTs */
	if (ecomdel == NULL) {
		/* Reset to default and process all routes. */
		for (ALL_LIST_ELEMENTS(vpn->export_rtl, node, nnode, ecom)) {
			ecommunity_free(&ecom);
			list_delete_node(vpn->export_rtl, node);
		}
	}

	/* Delete a specific export RT */
	else {
		node_to_del = NULL;

		for (ALL_LIST_ELEMENTS(vpn->export_rtl, node, nnode, ecom)) {
			if (ecommunity_match(ecom, ecomdel)) {
				ecommunity_free(&ecom);
				node_to_del = node;
				break;
			}
		}

		if (node_to_del)
			list_delete_node(vpn->export_rtl, node_to_del);
	}

	assert(vpn->export_rtl);
	if (list_isempty(vpn->export_rtl)) {
		UNSET_FLAG(vpn->flags, VNI_FLAG_EXPRT_CFGD);
		bgp_evpn_derive_auto_rt_export(bgp, vpn);
	}

	if (is_vni_live(vpn))
		bgp_evpn_handle_export_rt_change(bgp, vpn);
}

/*
 * Configure RD for VRF
 */
static void evpn_configure_vrf_rd(struct bgp *bgp_vrf, struct prefix_rd *rd)
{
	/* If we have already advertise type-5 routes with a diffrent RD, we
	 * have to delete and withdraw them firs
	 */
	bgp_evpn_handle_vrf_rd_change(bgp_vrf, 1);

	/* update RD */
	memcpy(&bgp_vrf->vrf_prd, rd, sizeof(struct prefix_rd));
	SET_FLAG(bgp_vrf->vrf_flags, BGP_VRF_RD_CFGD);

	/* We have a new RD for VRF.
	 * Advertise all type-5 routes again with the new RD
	 */
	bgp_evpn_handle_vrf_rd_change(bgp_vrf, 0);
}

/*
 * Unconfigure RD for VRF
 */
static void evpn_unconfigure_vrf_rd(struct bgp *bgp_vrf)
{
	/* If we have already advertise type-5 routes with a diffrent RD, we
	 * have to delete and withdraw them firs
	 */
	bgp_evpn_handle_vrf_rd_change(bgp_vrf, 1);

	/* fall back to default RD */
	bgp_evpn_derive_auto_rd_for_vrf(bgp_vrf);
	UNSET_FLAG(bgp_vrf->vrf_flags, BGP_VRF_RD_CFGD);

	/* We have a new RD for VRF.
	 * Advertise all type-5 routes again with the new RD
	 */
	bgp_evpn_handle_vrf_rd_change(bgp_vrf, 0);
}

/*
 * Configure RD for a VNI (vty handler)
 */
static void evpn_configure_rd(struct bgp *bgp, struct bgpevpn *vpn,
			      struct prefix_rd *rd)
{
	/* If the VNI is "live", we need to delete and withdraw this VNI's
	 * local routes with the prior RD first. Then, after updating RD,
	 * need to re-advertise.
	 */
	if (is_vni_live(vpn))
		bgp_evpn_handle_rd_change(bgp, vpn, 1);

	/* update RD */
	memcpy(&vpn->prd, rd, sizeof(struct prefix_rd));
	SET_FLAG(vpn->flags, VNI_FLAG_RD_CFGD);

	if (is_vni_live(vpn))
		bgp_evpn_handle_rd_change(bgp, vpn, 0);
}

/*
 * Unconfigure RD for a VNI (vty handler)
 */
static void evpn_unconfigure_rd(struct bgp *bgp, struct bgpevpn *vpn)
{
	/* If the VNI is "live", we need to delete and withdraw this VNI's
	 * local routes with the prior RD first. Then, after resetting RD
	 * to automatic value, need to re-advertise.
	 */
	if (is_vni_live(vpn))
		bgp_evpn_handle_rd_change(bgp, vpn, 1);

	/* reset RD to default */
	bgp_evpn_derive_auto_rd(bgp, vpn);

	if (is_vni_live(vpn))
		bgp_evpn_handle_rd_change(bgp, vpn, 0);
}

/*
 * Create VNI, if not already present (VTY handler). Mark as configured.
 */
static struct bgpevpn *evpn_create_update_vni(struct bgp *bgp, vni_t vni)
{
	struct bgpevpn *vpn;
	struct in_addr mcast_grp = {INADDR_ANY};

	if (!bgp->vnihash)
		return NULL;

	vpn = bgp_evpn_lookup_vni(bgp, vni);
	if (!vpn) {
		/* Check if this L2VNI is already configured as L3VNI */
		if (bgp_evpn_lookup_l3vni_l2vni_table(vni)) {
			flog_err(
				EC_BGP_VNI,
				"%u: Failed to create L2VNI %u, it is configured as L3VNI",
				bgp->vrf_id, vni);
			return NULL;
		}

		/* tenant vrf will be updated when we get local_vni_add from
		 * zebra
		 */
		vpn = bgp_evpn_new(bgp, vni, bgp->router_id, 0, mcast_grp);
		if (!vpn) {
			flog_err(
				EC_BGP_VNI,
				"%u: Failed to allocate VNI entry for VNI %u - at Config",
				bgp->vrf_id, vni);
			return NULL;
		}
	}

	/* Mark as configured. */
	SET_FLAG(vpn->flags, VNI_FLAG_CFGD);
	return vpn;
}

/*
 * Delete VNI. If VNI does not exist in the system (i.e., just
 * configuration), all that is needed is to free it. Otherwise,
 * any parameters configured for the VNI need to be reset (with
 * appropriate action) and the VNI marked as unconfigured; the
 * VNI will continue to exist, purely as a "learnt" entity.
 */
static int evpn_delete_vni(struct bgp *bgp, struct bgpevpn *vpn)
{
	assert(bgp->vnihash);

	if (!is_vni_live(vpn)) {
		bgp_evpn_free(bgp, vpn);
		return 0;
	}

	/* We need to take the unconfigure action for each parameter of this VNI
	 * that is configured. Some optimization is possible, but not worth the
	 * additional code for an operation that should be pretty rare.
	 */
	UNSET_FLAG(vpn->flags, VNI_FLAG_CFGD);

	/* First, deal with the export side - RD and export RT changes. */
	if (is_rd_configured(vpn))
		evpn_unconfigure_rd(bgp, vpn);
	if (is_export_rt_configured(vpn))
		evpn_unconfigure_export_rt(bgp, vpn, NULL);

	/* Next, deal with the import side. */
	if (is_import_rt_configured(vpn))
		evpn_unconfigure_import_rt(bgp, vpn, NULL);

	return 0;
}

/*
 * Display import RT mapping to VRFs (vty handler)
 * bgp_evpn: evpn bgp instance
 */
static void evpn_show_vrf_import_rts(struct vty *vty, struct bgp *bgp_evpn,
				     json_object *json)
{
	void *args[2];

	args[0] = vty;
	args[1] = json;

	hash_iterate(bgp_evpn->vrf_import_rt_hash,
		     (void (*)(struct hash_bucket *,
			       void *))show_vrf_import_rt_entry,
		     args);
}

/*
 * Display import RT mapping to VNIs (vty handler)
 */
static void evpn_show_import_rts(struct vty *vty, struct bgp *bgp,
				 json_object *json)
{
	void *args[2];

	args[0] = vty;
	args[1] = json;

	hash_iterate(
		bgp->import_rt_hash,
		(void (*)(struct hash_bucket *, void *))show_import_rt_entry,
		args);
}

/*
 * Display EVPN routes for all VNIs - vty handler.
 */
static void evpn_show_routes_vni_all(struct vty *vty, struct bgp *bgp,
				     struct in_addr vtep_ip, json_object *json,
				     int detail)
{
	uint32_t num_vnis;
	struct vni_walk_ctx wctx;

	num_vnis = hashcount(bgp->vnihash);
	if (!num_vnis)
		return;
	memset(&wctx, 0, sizeof(struct vni_walk_ctx));
	wctx.bgp = bgp;
	wctx.vty = vty;
	wctx.vtep_ip = vtep_ip;
	wctx.json = json;
	wctx.detail = detail;
	hash_iterate(bgp->vnihash, (void (*)(struct hash_bucket *,
					     void *))show_vni_routes_hash,
		     &wctx);
}

/*
 * Display EVPN routes for a VNI -- for specific type-3 route (vty handler).
 */
static void evpn_show_route_vni_multicast(struct vty *vty, struct bgp *bgp,
					  vni_t vni, struct in_addr orig_ip,
					  json_object *json)
{
	struct bgpevpn *vpn;
	struct prefix_evpn p;
	struct bgp_node *rn;
	struct bgp_path_info *pi;
	uint32_t path_cnt = 0;
	afi_t afi;
	safi_t safi;
	json_object *json_paths = NULL;

	afi = AFI_L2VPN;
	safi = SAFI_EVPN;

	/* Locate VNI. */
	vpn = bgp_evpn_lookup_vni(bgp, vni);
	if (!vpn) {
		vty_out(vty, "VNI not found\n");
		return;
	}

	/* See if route exists. */
	build_evpn_type3_prefix(&p, orig_ip);
	rn = bgp_node_lookup(vpn->route_table, (struct prefix *)&p);
	if (!rn || !bgp_node_has_bgp_path_info_data(rn)) {
		if (!json)
			vty_out(vty, "%% Network not in table\n");
		return;
	}

	if (json)
		json_paths = json_object_new_array();

	/* Prefix and num paths displayed once per prefix. */
	route_vty_out_detail_header(vty, bgp, rn, NULL, afi, safi, json);

	/* Display each path for this prefix. */
	for (pi = bgp_node_get_bgp_path_info(rn); pi; pi = pi->next) {
		json_object *json_path = NULL;

		if (json)
			json_path = json_object_new_array();

		route_vty_out_detail(vty, bgp, rn, pi, afi, safi,
				     json_path);

		if (json)
			json_object_array_add(json_paths, json_path);

		path_cnt++;
	}

	if (json) {
		if (path_cnt)
			json_object_object_add(json, "paths", json_paths);

		json_object_int_add(json, "numPaths", path_cnt);
	} else {
		vty_out(vty, "\nDisplayed %u paths for requested prefix\n",
			path_cnt);
	}
}

/*
 * Display EVPN routes for a VNI -- for specific MAC and/or IP (vty handler).
 * By definition, only matching type-2 route will be displayed.
 */
static void evpn_show_route_vni_macip(struct vty *vty, struct bgp *bgp,
				      vni_t vni, struct ethaddr *mac,
				      struct ipaddr *ip, json_object *json)
{
	struct bgpevpn *vpn;
	struct prefix_evpn p;
	struct bgp_node *rn;
	struct bgp_path_info *pi;
	uint32_t path_cnt = 0;
	afi_t afi;
	safi_t safi;
	json_object *json_paths = NULL;

	afi = AFI_L2VPN;
	safi = SAFI_EVPN;

	/* Locate VNI. */
	vpn = bgp_evpn_lookup_vni(bgp, vni);
	if (!vpn) {
		if (!json)
			vty_out(vty, "VNI not found\n");
		return;
	}

	/* See if route exists. Look for both non-sticky and sticky. */
	build_evpn_type2_prefix(&p, mac, ip);
	rn = bgp_node_lookup(vpn->route_table, (struct prefix *)&p);
	if (!rn || !bgp_node_has_bgp_path_info_data(rn)) {
		if (!json)
			vty_out(vty, "%% Network not in table\n");
		return;
	}

	if (json)
		json_paths = json_object_new_array();

	/* Prefix and num paths displayed once per prefix. */
	route_vty_out_detail_header(vty, bgp, rn, NULL, afi, safi, json);

	/* Display each path for this prefix. */
	for (pi = bgp_node_get_bgp_path_info(rn); pi; pi = pi->next) {
		json_object *json_path = NULL;

		if (json)
			json_path = json_object_new_array();

		route_vty_out_detail(vty, bgp, rn, pi, afi, safi,
				     json_path);

		if (json)
			json_object_array_add(json_paths, json_path);

		path_cnt++;
	}

	if (json) {
		if (path_cnt)
			json_object_object_add(json, "paths", json_paths);

		json_object_int_add(json, "numPaths", path_cnt);
	} else {
		vty_out(vty, "\nDisplayed %u paths for requested prefix\n",
			path_cnt);
	}
}

/* Disaplay EVPN routes for a ESI - VTY handler */
static void evpn_show_routes_esi(struct vty *vty, struct bgp *bgp,
				 esi_t *esi, json_object *json)
{
	struct evpnes *es = NULL;

	/* locate the ES */
	es = bgp_evpn_lookup_es(bgp, esi);
	if (!es) {
		if (!json)
			vty_out(vty, "ESI not found\n");
		return;
	}

	show_esi_routes(bgp, es, vty, json);
}

/*
 * Display EVPN routes for a VNI - vty handler.
 * If 'type' is non-zero, only routes matching that type are shown.
 * If the vtep_ip is non zero, only routes behind that vtep are shown
 */
static void evpn_show_routes_vni(struct vty *vty, struct bgp *bgp, vni_t vni,
				 int type, struct in_addr vtep_ip,
				 json_object *json)
{
	struct bgpevpn *vpn;

	/* Locate VNI. */
	vpn = bgp_evpn_lookup_vni(bgp, vni);
	if (!vpn) {
		if (!json)
			vty_out(vty, "VNI not found\n");
		return;
	}

	/* Walk this VNI's route table and display appropriate routes. */
	show_vni_routes(bgp, vpn, type, vty, vtep_ip, json, 0);
}

/*
 * Display BGP EVPN routing table -- for specific RD and MAC and/or
 * IP (vty handler). By definition, only matching type-2 route will be
 * displayed.
 */
static void evpn_show_route_rd_macip(struct vty *vty, struct bgp *bgp,
				     struct prefix_rd *prd, struct ethaddr *mac,
				     struct ipaddr *ip, json_object *json)
{
	struct prefix_evpn p;
	struct bgp_node *rn;
	struct bgp_path_info *pi;
	afi_t afi;
	safi_t safi;
	uint32_t path_cnt = 0;
	json_object *json_paths = NULL;
	char prefix_str[BUFSIZ];

	afi = AFI_L2VPN;
	safi = SAFI_EVPN;

	/* See if route exists. Look for both non-sticky and sticky. */
	build_evpn_type2_prefix(&p, mac, ip);
	rn = bgp_afi_node_lookup(bgp->rib[afi][safi], afi, safi,
				 (struct prefix *)&p, prd);
	if (!rn || !bgp_node_has_bgp_path_info_data(rn)) {
		if (!json)
			vty_out(vty, "%% Network not in table\n");
		return;
	}

	bgp_evpn_route2str((struct prefix_evpn *)&p, prefix_str,
			   sizeof(prefix_str));

	/* Prefix and num paths displayed once per prefix. */
	route_vty_out_detail_header(vty, bgp, rn, prd, afi, safi, json);

	if (json)
		json_paths = json_object_new_array();

	/* Display each path for this prefix. */
	for (pi = bgp_node_get_bgp_path_info(rn); pi; pi = pi->next) {
		json_object *json_path = NULL;

		if (json)
			json_path = json_object_new_array();

		route_vty_out_detail(vty, bgp, rn, pi, afi, safi,
				     json_path);

		if (json)
			json_object_array_add(json_paths, json_path);

		path_cnt++;
	}

	if (json && path_cnt) {
		if (path_cnt)
			json_object_object_add(json, prefix_str, json_paths);
		json_object_int_add(json, "numPaths", path_cnt);
	} else {
		vty_out(vty, "\nDisplayed %u paths for requested prefix\n",
			path_cnt);
	}
}

/*
 * Display BGP EVPN routing table -- for specific RD (vty handler)
 * If 'type' is non-zero, only routes matching that type are shown.
 */
static void evpn_show_route_rd(struct vty *vty, struct bgp *bgp,
			       struct prefix_rd *prd, int type,
			       json_object *json)
{
	struct bgp_node *rd_rn;
	struct bgp_table *table;
	struct bgp_node *rn;
	struct bgp_path_info *pi;
	int rd_header = 1;
	afi_t afi;
	safi_t safi;
	uint32_t prefix_cnt, path_cnt;
	char rd_str[RD_ADDRSTRLEN];
	json_object *json_rd = NULL;
	int add_rd_to_json = 0;

	afi = AFI_L2VPN;
	safi = SAFI_EVPN;
	prefix_cnt = path_cnt = 0;

	prefix_rd2str((struct prefix_rd *)prd, rd_str, sizeof(rd_str));

	rd_rn = bgp_node_lookup(bgp->rib[afi][safi], (struct prefix *)prd);
	if (!rd_rn)
		return;

	table = bgp_node_get_bgp_table_info(rd_rn);
	if (table == NULL)
		return;

	if (json) {
		json_rd = json_object_new_object();
		json_object_string_add(json_rd, "rd", rd_str);
	}

	/* Display all prefixes with this RD. */
	for (rn = bgp_table_top(table); rn; rn = bgp_route_next(rn)) {
		struct prefix_evpn *evp = (struct prefix_evpn *)&rn->p;
		json_object *json_prefix = NULL;
		json_object *json_paths = NULL;
		char prefix_str[BUFSIZ];
		int add_prefix_to_json = 0;

		bgp_evpn_route2str((struct prefix_evpn *)&rn->p, prefix_str,
				   sizeof(prefix_str));

		if (type && evp->prefix.route_type != type)
			continue;

		if (json)
			json_prefix = json_object_new_object();

		pi = bgp_node_get_bgp_path_info(rn);
		if (pi) {
			/* RD header and legend - once overall. */
			if (rd_header && !json) {
				vty_out(vty,
					"EVPN type-2 prefix: [2]:[EthTag]:[MAClen]:[MAC]\n");
				vty_out(vty,
					"EVPN type-3 prefix: [3]:[EthTag]:[IPlen]:[OrigIP]\n");
				vty_out(vty,
					"EVPN type-5 prefix: [5]:[EthTag]:[IPlen]:[IP]\n\n");
				rd_header = 0;
			}

			/* Prefix and num paths displayed once per prefix. */
			route_vty_out_detail_header(vty, bgp, rn, prd, afi,
						    safi, json_prefix);

			prefix_cnt++;
		}

		if (json)
			json_paths = json_object_new_array();

		/* Display each path for this prefix. */
		for (; pi; pi = pi->next) {
			json_object *json_path = NULL;

			if (json)
				json_path = json_object_new_array();

			route_vty_out_detail(vty, bgp, rn, pi, afi, safi,
					     json_path);

			if (json)
				json_object_array_add(json_paths, json_path);

			path_cnt++;
			add_prefix_to_json = 1;
			add_rd_to_json = 1;
		}

		if (json && add_prefix_to_json) {
			json_object_object_add(json_prefix, "paths",
					       json_paths);
			json_object_object_add(json_rd, prefix_str,
					       json_prefix);
		}
	}

	if (json && add_rd_to_json)
		json_object_object_add(json, rd_str, json_rd);

	if (json) {
		json_object_int_add(json, "numPrefix", prefix_cnt);
		json_object_int_add(json, "numPaths", path_cnt);
	} else {
		if (prefix_cnt == 0)
			vty_out(vty, "No prefixes exist with this RD%s\n",
				type ? " (of requested type)" : "");
		else
			vty_out(vty,
				"\nDisplayed %u prefixes (%u paths) with this RD%s\n",
				prefix_cnt, path_cnt,
				type ? " (of requested type)" : "");
	}
}

/*
 * Display BGP EVPN routing table - all routes (vty handler).
 * If 'type' is non-zero, only routes matching that type are shown.
 */
static void evpn_show_all_routes(struct vty *vty, struct bgp *bgp, int type,
				 json_object *json, int detail)
{
	struct bgp_node *rd_rn;
	struct bgp_table *table;
	struct bgp_node *rn;
	struct bgp_path_info *pi;
	int header = detail ? 0 : 1;
	int rd_header;
	afi_t afi;
	safi_t safi;
	uint32_t prefix_cnt, path_cnt;

	afi = AFI_L2VPN;
	safi = SAFI_EVPN;
	prefix_cnt = path_cnt = 0;

	/* EVPN routing table is a 2-level table with the first level being
	 * the RD.
	 */
	for (rd_rn = bgp_table_top(bgp->rib[afi][safi]); rd_rn;
	     rd_rn = bgp_route_next(rd_rn)) {
		char rd_str[RD_ADDRSTRLEN];
		json_object *json_rd = NULL; /* contains routes for an RD */
		int add_rd_to_json = 0;
		uint64_t tbl_ver;

		table = bgp_node_get_bgp_table_info(rd_rn);
		if (table == NULL)
			continue;

		tbl_ver = table->version;
		prefix_rd2str((struct prefix_rd *)&rd_rn->p, rd_str,
			      sizeof(rd_str));

		if (json) {
			json_rd = json_object_new_object();
			json_object_string_add(json_rd, "rd", rd_str);
		}

		rd_header = 1;

		/* Display all prefixes for an RD */
		for (rn = bgp_table_top(table); rn; rn = bgp_route_next(rn)) {
			json_object *json_prefix =
				NULL; /* contains prefix under a RD */
			json_object *json_paths =
				NULL; /* array of paths under a prefix*/
			struct prefix_evpn *evp = (struct prefix_evpn *)&rn->p;
			char prefix_str[BUFSIZ];
			int add_prefix_to_json = 0;

			bgp_evpn_route2str((struct prefix_evpn *)&rn->p,
					   prefix_str, sizeof(prefix_str));

			if (type && evp->prefix.route_type != type)
				continue;

			pi = bgp_node_get_bgp_path_info(rn);
			if (pi) {
				/* Overall header/legend displayed once. */
				if (header) {
					bgp_evpn_show_route_header(vty, bgp,
								   tbl_ver,
								   json);
					if (!json)
						vty_out(vty,
							"%19s Extended Community\n"
							, " ");
					header = 0;
				}

				/* RD header - per RD. */
				if (rd_header) {
					bgp_evpn_show_route_rd_header(
						vty, rd_rn, NULL, rd_str,
						RD_ADDRSTRLEN);
					rd_header = 0;
				}

				prefix_cnt++;
			}

			if (json) {
				json_prefix = json_object_new_object();
				json_paths = json_object_new_array();
				json_object_string_add(json_prefix, "prefix",
						       prefix_str);
				json_object_int_add(json_prefix, "prefixLen",
						    rn->p.prefixlen);
			}

			/* Prefix and num paths displayed once per prefix. */
			if (detail)
				route_vty_out_detail_header(
					vty, bgp, rn,
					(struct prefix_rd *)&rd_rn->p,
					AFI_L2VPN, SAFI_EVPN, json_prefix);

			/* For EVPN, the prefix is displayed for each path (to
			 * fit in
			 * with code that already exists).
			 */
			for (; pi; pi = pi->next) {
				json_object *json_path = NULL;
				path_cnt++;
				add_prefix_to_json = 1;
				add_rd_to_json = 1;

				if (json)
					json_path = json_object_new_array();

				if (detail) {
					route_vty_out_detail(
						vty, bgp, rn, pi, AFI_L2VPN,
						SAFI_EVPN, json_path);
				} else
					route_vty_out(vty, &rn->p, pi, 0,
						      SAFI_EVPN, json_path);

				if (json)
					json_object_array_add(json_paths,
							      json_path);
			}

			if (json && add_prefix_to_json) {
				json_object_object_add(json_prefix, "paths",
						       json_paths);
				json_object_object_add(json_rd, prefix_str,
						       json_prefix);
			}
		}

		if (json && add_rd_to_json)
			json_object_object_add(json, rd_str, json_rd);
	}

	if (json) {
		json_object_int_add(json, "numPrefix", prefix_cnt);
		json_object_int_add(json, "numPaths", path_cnt);
	} else {
		if (prefix_cnt == 0) {
			vty_out(vty, "No EVPN prefixes %sexist\n",
				type ? "(of requested type) " : "");
		} else {
			vty_out(vty, "\nDisplayed %u prefixes (%u paths)%s\n",
				prefix_cnt, path_cnt,
				type ? " (of requested type)" : "");
		}
	}
}

/* Display specific ES */
static void evpn_show_es(struct vty *vty, struct bgp *bgp, esi_t *esi,
			 json_object *json)
{
	struct evpnes *es = NULL;

	es = bgp_evpn_lookup_es(bgp, esi);
	if (es) {
		display_es(vty, es, json);
	} else {
		if (json) {
			vty_out(vty, "{}\n");
		} else {
			vty_out(vty, "ESI not found\n");
			return;
		}
	}
}

/* Display all ESs */
static void evpn_show_all_es(struct vty *vty, struct bgp *bgp,
			     json_object *json)
{
	void *args[2];

	if (!json)
		vty_out(vty, "%-30s %-6s %-21s %-15s %-6s\n",
			"ESI", "Type", "RD", "Originator-IP", "#VTEPs");

	/* print all ESs */
	args[0] = vty;
	args[1] = json;
	hash_iterate(bgp->esihash,
		     (void (*)(struct hash_bucket *, void *))show_es_entry,
		     args);
}

/*
 * Display specified VNI (vty handler)
 */
static void evpn_show_vni(struct vty *vty, struct bgp *bgp, vni_t vni,
			  json_object *json)
{
	uint8_t found = 0;
	struct bgpevpn *vpn;

	vpn = bgp_evpn_lookup_vni(bgp, vni);
	if (vpn) {
		found = 1;
		display_vni(vty, vpn, json);
	} else {
		struct bgp *bgp_temp;
		struct listnode *node = NULL;

		for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp_temp)) {
			if (bgp_temp->l3vni == vni) {
				found = 1;
				display_l3vni(vty, bgp_temp, json);
			}
		}
	}

	if (!found) {
		if (json) {
			vty_out(vty, "{}\n");
		} else {
			vty_out(vty, "VNI not found\n");
			return;
		}
	}
}

/*
 * Display a VNI (upon user query).
 */
static void evpn_show_all_vnis(struct vty *vty, struct bgp *bgp,
			       json_object *json)
{
	void *args[2];
	struct bgp *bgp_temp = NULL;
	struct listnode *node;


	if (!json) {
		vty_out(vty, "Flags: * - Kernel\n");
		vty_out(vty, "  %-10s %-4s %-21s %-25s %-25s %-37s\n", "VNI",
			"Type", "RD", "Import RT", "Export RT", "Tenant VRF");
	}

	/* print all L2 VNIS */
	args[0] = vty;
	args[1] = json;
	hash_iterate(bgp->vnihash,
		     (void (*)(struct hash_bucket *, void *))show_vni_entry,
		     args);

	/* print all L3 VNIs */
	for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp_temp))
		show_l3vni_entry(vty, bgp_temp, json);
}

/*
 * evpn - enable advertisement of svi MAC-IP
 */
static void evpn_set_advertise_svi_macip(struct bgp *bgp, struct bgpevpn *vpn,
					 uint32_t set)
{
	if (!vpn) {
		if (set && bgp->evpn_info->advertise_svi_macip)
			return;
		else if (!set && !bgp->evpn_info->advertise_svi_macip)
			return;

		bgp->evpn_info->advertise_svi_macip = set;
		bgp_zebra_advertise_svi_macip(bgp,
					bgp->evpn_info->advertise_svi_macip, 0);
	} else {
		if (set && vpn->advertise_svi_macip)
			return;
		else if (!set && !vpn->advertise_svi_macip)
			return;

		vpn->advertise_svi_macip = set;
		bgp_zebra_advertise_svi_macip(bgp, vpn->advertise_svi_macip,
					      vpn->vni);
	}
}

/*
 * evpn - enable advertisement of default g/w
 */
static void evpn_set_advertise_default_gw(struct bgp *bgp, struct bgpevpn *vpn)
{
	if (!vpn) {
		if (bgp->advertise_gw_macip)
			return;

		bgp->advertise_gw_macip = 1;
		bgp_zebra_advertise_gw_macip(bgp, bgp->advertise_gw_macip, 0);
	} else {
		if (vpn->advertise_gw_macip)
			return;

		vpn->advertise_gw_macip = 1;
		bgp_zebra_advertise_gw_macip(bgp, vpn->advertise_gw_macip,
					     vpn->vni);
	}
	return;
}

/*
 * evpn - disable advertisement of default g/w
 */
static void evpn_unset_advertise_default_gw(struct bgp *bgp,
					    struct bgpevpn *vpn)
{
	if (!vpn) {
		if (!bgp->advertise_gw_macip)
			return;

		bgp->advertise_gw_macip = 0;
		bgp_zebra_advertise_gw_macip(bgp, bgp->advertise_gw_macip, 0);
	} else {
		if (!vpn->advertise_gw_macip)
			return;

		vpn->advertise_gw_macip = 0;
		bgp_zebra_advertise_gw_macip(bgp, vpn->advertise_gw_macip,
					     vpn->vni);
	}
	return;
}

/*
 * evpn - enable advertisement of default g/w
 */
static void evpn_process_default_originate_cmd(struct bgp *bgp_vrf,
					       afi_t afi, bool add)
{
	safi_t safi = SAFI_UNICAST; /* ipv4/ipv6 unicast */

	if (add) {
		/* bail if we are already advertising default route */
		if (evpn_default_originate_set(bgp_vrf, afi, safi))
			return;

		if (afi == AFI_IP)
			SET_FLAG(bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
				 BGP_L2VPN_EVPN_DEFAULT_ORIGINATE_IPV4);
		else if (afi == AFI_IP6)
			SET_FLAG(bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
				 BGP_L2VPN_EVPN_DEFAULT_ORIGINATE_IPV6);
	} else {
		/* bail out if we havent advertised the default route */
		if (!evpn_default_originate_set(bgp_vrf, afi, safi))
			return;
		if (afi == AFI_IP)
			UNSET_FLAG(bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
				   BGP_L2VPN_EVPN_DEFAULT_ORIGINATE_IPV4);
		else if (afi == AFI_IP6)
			UNSET_FLAG(bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
				   BGP_L2VPN_EVPN_DEFAULT_ORIGINATE_IPV6);
	}

	bgp_evpn_install_uninstall_default_route(bgp_vrf, afi, safi, add);
}

/*
 * evpn - enable advertisement of default g/w
 */
static void evpn_set_advertise_subnet(struct bgp *bgp,
				      struct bgpevpn *vpn)
{
	if (vpn->advertise_subnet)
		return;

	vpn->advertise_subnet = 1;
	bgp_zebra_advertise_subnet(bgp, vpn->advertise_subnet, vpn->vni);
}

/*
 * evpn - disable advertisement of default g/w
 */
static void evpn_unset_advertise_subnet(struct bgp *bgp, struct bgpevpn *vpn)
{
	if (!vpn->advertise_subnet)
		return;

	vpn->advertise_subnet = 0;
	bgp_zebra_advertise_subnet(bgp, vpn->advertise_subnet, vpn->vni);
}

/*
 * EVPN (VNI advertisement) enabled. Register with zebra.
 */
static void evpn_set_advertise_all_vni(struct bgp *bgp)
{
	bgp->advertise_all_vni = 1;
	bgp_set_evpn(bgp);
	bgp_zebra_advertise_all_vni(bgp, bgp->advertise_all_vni);
}

/*
 * EVPN (VNI advertisement) disabled. De-register with zebra. Cleanup VNI
 * cache, EVPN routes (delete and withdraw from peers).
 */
static void evpn_unset_advertise_all_vni(struct bgp *bgp)
{
	bgp->advertise_all_vni = 0;
	bgp_set_evpn(bgp_get_default());
	bgp_zebra_advertise_all_vni(bgp, bgp->advertise_all_vni);
	bgp_evpn_cleanup_on_disable(bgp);
}

/*
 * EVPN - use RFC8365 to auto-derive RT
 */
static void evpn_set_advertise_autort_rfc8365(struct bgp *bgp)
{
	bgp->advertise_autort_rfc8365 = 1;
	bgp_evpn_handle_autort_change(bgp);
}

/*
 * EVPN - don't use RFC8365 to auto-derive RT
 */
static void evpn_unset_advertise_autort_rfc8365(struct bgp *bgp)
{
	bgp->advertise_autort_rfc8365 = 0;
	bgp_evpn_handle_autort_change(bgp);
}

static void write_vni_config(struct vty *vty, struct bgpevpn *vpn)
{
	char buf1[RD_ADDRSTRLEN];
	char *ecom_str;
	struct listnode *node, *nnode;
	struct ecommunity *ecom;

	if (is_vni_configured(vpn)) {
		vty_out(vty, "  vni %d\n", vpn->vni);
		if (is_rd_configured(vpn))
			vty_out(vty, "   rd %s\n",
				prefix_rd2str(&vpn->prd, buf1, sizeof(buf1)));

		if (is_import_rt_configured(vpn)) {
			for (ALL_LIST_ELEMENTS(vpn->import_rtl, node, nnode,
					       ecom)) {
				ecom_str = ecommunity_ecom2str(
					ecom, ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
				vty_out(vty, "   route-target import %s\n",
					ecom_str);
				XFREE(MTYPE_ECOMMUNITY_STR, ecom_str);
			}
		}

		if (is_export_rt_configured(vpn)) {
			for (ALL_LIST_ELEMENTS(vpn->export_rtl, node, nnode,
					       ecom)) {
				ecom_str = ecommunity_ecom2str(
					ecom, ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
				vty_out(vty, "   route-target export %s\n",
					ecom_str);
				XFREE(MTYPE_ECOMMUNITY_STR, ecom_str);
			}
		}

		if (vpn->advertise_gw_macip)
			vty_out(vty, "   advertise-default-gw\n");

		if (vpn->advertise_svi_macip)
			vty_out(vty, "   advertise-svi-ip\n");

		if (vpn->advertise_subnet)
			vty_out(vty, "   advertise-subnet\n");

		vty_out(vty, "  exit-vni\n");
	}
}

#ifndef VTYSH_EXTRACT_PL
#include "bgpd/bgp_evpn_vty_clippy.c"
#endif

DEFPY(bgp_evpn_flood_control,
      bgp_evpn_flood_control_cmd,
      "[no$no] flooding <disable$disable|head-end-replication$her>",
      NO_STR
      "Specify handling for BUM packets\n"
      "Do not flood any BUM packets\n"
      "Flood BUM packets using head-end replication\n")
{
	struct bgp *bgp = VTY_GET_CONTEXT(bgp);
	enum vxlan_flood_control flood_ctrl;

	if (!bgp)
		return CMD_WARNING;

	if (disable && !no)
		flood_ctrl = VXLAN_FLOOD_DISABLED;
	else if (her || no)
		flood_ctrl = VXLAN_FLOOD_HEAD_END_REPL;
	else
		return CMD_WARNING;

	if (bgp->vxlan_flood_ctrl == flood_ctrl)
		return CMD_SUCCESS;

	bgp->vxlan_flood_ctrl = flood_ctrl;
	bgp_evpn_flood_control_change(bgp);

	return CMD_SUCCESS;
}

DEFUN (bgp_evpn_advertise_default_gw_vni,
       bgp_evpn_advertise_default_gw_vni_cmd,
       "advertise-default-gw",
       "Advertise default g/w mac-ip routes in EVPN for a VNI\n")
{
	struct bgp *bgp = VTY_GET_CONTEXT(bgp);
	VTY_DECLVAR_CONTEXT_SUB(bgpevpn, vpn);

	if (!bgp)
		return CMD_WARNING;

	evpn_set_advertise_default_gw(bgp, vpn);

	return CMD_SUCCESS;
}

DEFUN (no_bgp_evpn_advertise_default_vni_gw,
       no_bgp_evpn_advertise_default_gw_vni_cmd,
       "no advertise-default-gw",
       NO_STR
       "Withdraw default g/w mac-ip routes from EVPN for a VNI\n")
{
	struct bgp *bgp = VTY_GET_CONTEXT(bgp);
	VTY_DECLVAR_CONTEXT_SUB(bgpevpn, vpn);

	if (!bgp)
		return CMD_WARNING;

	evpn_unset_advertise_default_gw(bgp, vpn);

	return CMD_SUCCESS;
}


DEFUN (bgp_evpn_advertise_default_gw,
       bgp_evpn_advertise_default_gw_cmd,
       "advertise-default-gw",
       "Advertise All default g/w mac-ip routes in EVPN\n")
{
	struct bgp *bgp = VTY_GET_CONTEXT(bgp);

	if (!bgp)
		return CMD_WARNING;

	if (!EVPN_ENABLED(bgp)) {
		vty_out(vty,
			"This command is only supported under the EVPN VRF\n");
		return CMD_WARNING;
	}

	evpn_set_advertise_default_gw(bgp, NULL);

	return CMD_SUCCESS;
}

DEFUN (no_bgp_evpn_advertise_default_gw,
       no_bgp_evpn_advertise_default_gw_cmd,
       "no advertise-default-gw",
       NO_STR
       "Withdraw All default g/w mac-ip routes from EVPN\n")
{
	struct bgp *bgp = VTY_GET_CONTEXT(bgp);

	if (!bgp)
		return CMD_WARNING;

	if (!EVPN_ENABLED(bgp)) {
		vty_out(vty,
			"This command is only supported under the EVPN VRF\n");
		return CMD_WARNING;
	}

	evpn_unset_advertise_default_gw(bgp, NULL);

	return CMD_SUCCESS;
}

DEFUN (bgp_evpn_advertise_all_vni,
       bgp_evpn_advertise_all_vni_cmd,
       "advertise-all-vni",
       "Advertise All local VNIs\n")
{
	struct bgp *bgp = VTY_GET_CONTEXT(bgp);
	struct bgp *bgp_evpn = NULL;

	if (!bgp)
		return CMD_WARNING;

	bgp_evpn = bgp_get_evpn();
	if (bgp_evpn && bgp_evpn != bgp) {
		vty_out(vty, "%% Please unconfigure EVPN in VRF %s\n",
			bgp_evpn->name);
		return CMD_WARNING_CONFIG_FAILED;
	}

	evpn_set_advertise_all_vni(bgp);
	return CMD_SUCCESS;
}

DEFUN (no_bgp_evpn_advertise_all_vni,
       no_bgp_evpn_advertise_all_vni_cmd,
       "no advertise-all-vni",
       NO_STR
       "Advertise All local VNIs\n")
{
	struct bgp *bgp = VTY_GET_CONTEXT(bgp);

	if (!bgp)
		return CMD_WARNING;
	evpn_unset_advertise_all_vni(bgp);
	return CMD_SUCCESS;
}

DEFUN (bgp_evpn_advertise_autort_rfc8365,
       bgp_evpn_advertise_autort_rfc8365_cmd,
       "autort rfc8365-compatible",
       "Auto-derivation of RT\n"
       "Auto-derivation of RT using RFC8365\n")
{
	struct bgp *bgp = VTY_GET_CONTEXT(bgp);

	if (!bgp)
		return CMD_WARNING;
	evpn_set_advertise_autort_rfc8365(bgp);
	return CMD_SUCCESS;
}

DEFUN (no_bgp_evpn_advertise_autort_rfc8365,
       no_bgp_evpn_advertise_autort_rfc8365_cmd,
       "no autort rfc8365-compatible",
       NO_STR
       "Auto-derivation of RT\n"
       "Auto-derivation of RT using RFC8365\n")
{
	struct bgp *bgp = VTY_GET_CONTEXT(bgp);

	if (!bgp)
		return CMD_WARNING;
	evpn_unset_advertise_autort_rfc8365(bgp);
	return CMD_SUCCESS;
}

DEFUN (bgp_evpn_default_originate,
       bgp_evpn_default_originate_cmd,
       "default-originate <ipv4 | ipv6>",
       "originate a default route\n"
       "ipv4 address family\n"
       "ipv6 address family\n")
{
	afi_t afi = 0;
	int idx_afi = 0;
	struct bgp *bgp_vrf = VTY_GET_CONTEXT(bgp);

	if (!bgp_vrf)
		return CMD_WARNING;
	argv_find_and_parse_afi(argv, argc, &idx_afi, &afi);
	evpn_process_default_originate_cmd(bgp_vrf, afi, true);
	return CMD_SUCCESS;
}

DEFUN (no_bgp_evpn_default_originate,
       no_bgp_evpn_default_originate_cmd,
       "no default-originate <ipv4 | ipv6>",
       NO_STR
       "withdraw a default route\n"
       "ipv4 address family\n"
       "ipv6 address family\n")
{
	afi_t afi = 0;
	int idx_afi = 0;
	struct bgp *bgp_vrf = VTY_GET_CONTEXT(bgp);

	if (!bgp_vrf)
		return CMD_WARNING;
	argv_find_and_parse_afi(argv, argc, &idx_afi, &afi);
	evpn_process_default_originate_cmd(bgp_vrf, afi, false);
	return CMD_SUCCESS;
}

DEFPY (dup_addr_detection,
       dup_addr_detection_cmd,
       "dup-addr-detection [max-moves (2-1000)$max_moves_val time (2-1800)$time_val]",
       "Duplicate address detection\n"
       "Max allowed moves before address detected as duplicate\n"
       "Num of max allowed moves (2-1000) default 5\n"
       "Duplicate address detection time\n"
       "Time in seconds (2-1800) default 180\n")
{
	struct bgp *bgp_vrf = VTY_GET_CONTEXT(bgp);

	if (!bgp_vrf)
		return CMD_WARNING;

	if (!EVPN_ENABLED(bgp_vrf)) {
		vty_out(vty,
			"This command is only supported under the EVPN VRF\n");
		return CMD_WARNING;
	}

	bgp_vrf->evpn_info->dup_addr_detect = true;

	if (time_val)
		bgp_vrf->evpn_info->dad_time = time_val;
	if (max_moves_val)
		bgp_vrf->evpn_info->dad_max_moves = max_moves_val;

	bgp_zebra_dup_addr_detection(bgp_vrf);

	return CMD_SUCCESS;
}

DEFPY (dup_addr_detection_auto_recovery,
       dup_addr_detection_auto_recovery_cmd,
       "dup-addr-detection freeze <permanent |(30-3600)$freeze_time_val>",
       "Duplicate address detection\n"
       "Duplicate address detection freeze\n"
       "Duplicate address detection permanent freeze\n"
       "Duplicate address detection freeze time (30-3600)\n")
{
	struct bgp *bgp_vrf = VTY_GET_CONTEXT(bgp);
	uint32_t freeze_time = freeze_time_val;

	if (!bgp_vrf)
		return CMD_WARNING;

	if (!EVPN_ENABLED(bgp_vrf)) {
		vty_out(vty,
			"This command is only supported under the EVPN VRF\n");
		return CMD_WARNING;
	}

	bgp_vrf->evpn_info->dup_addr_detect = true;
	bgp_vrf->evpn_info->dad_freeze = true;
	bgp_vrf->evpn_info->dad_freeze_time = freeze_time;

	bgp_zebra_dup_addr_detection(bgp_vrf);

	return CMD_SUCCESS;
}

DEFPY (no_dup_addr_detection,
       no_dup_addr_detection_cmd,
       "no dup-addr-detection [max-moves (2-1000)$max_moves_val time (2-1800)$time_val | freeze <permanent$permanent_val | (30-3600)$freeze_time_val>]",
       NO_STR
       "Duplicate address detection\n"
       "Max allowed moves before address detected as duplicate\n"
       "Num of max allowed moves (2-1000) default 5\n"
       "Duplicate address detection time\n"
       "Time in seconds (2-1800) default 180\n"
       "Duplicate address detection freeze\n"
       "Duplicate address detection permanent freeze\n"
       "Duplicate address detection freeze time (30-3600)\n")
{
	struct bgp *bgp_vrf = VTY_GET_CONTEXT(bgp);
	uint32_t max_moves = (uint32_t)max_moves_val;
	uint32_t freeze_time = (uint32_t)freeze_time_val;

	if (!bgp_vrf)
		return CMD_WARNING;

	if (!EVPN_ENABLED(bgp_vrf)) {
		vty_out(vty,
			"This command is only supported under the EVPN VRF\n");
		return CMD_WARNING;
	}

	if (argc == 2) {
		if (!bgp_vrf->evpn_info->dup_addr_detect)
			return CMD_SUCCESS;
		/* Reset all parameters to default. */
		bgp_vrf->evpn_info->dup_addr_detect = false;
		bgp_vrf->evpn_info->dad_time = EVPN_DAD_DEFAULT_TIME;
		bgp_vrf->evpn_info->dad_max_moves = EVPN_DAD_DEFAULT_MAX_MOVES;
		bgp_vrf->evpn_info->dad_freeze = false;
		bgp_vrf->evpn_info->dad_freeze_time = 0;
	} else {
		if (max_moves) {
			if (bgp_vrf->evpn_info->dad_max_moves != max_moves) {
				vty_out(vty,
				"%% Value does not match with config\n");
				return CMD_SUCCESS;
			}
			bgp_vrf->evpn_info->dad_max_moves =
				EVPN_DAD_DEFAULT_MAX_MOVES;
		}

		if (time_val) {
			if (bgp_vrf->evpn_info->dad_time != time_val) {
				vty_out(vty,
				"%% Value does not match with config\n");
				return CMD_SUCCESS;
			}
			bgp_vrf->evpn_info->dad_time = EVPN_DAD_DEFAULT_TIME;
		}

		if (freeze_time) {
			if (bgp_vrf->evpn_info->dad_freeze_time
			    != freeze_time) {
				vty_out(vty,
				"%% Value does not match with config\n");
				return CMD_SUCCESS;
			}
			bgp_vrf->evpn_info->dad_freeze_time = 0;
			bgp_vrf->evpn_info->dad_freeze = false;
		}

		if (permanent_val) {
			if (bgp_vrf->evpn_info->dad_freeze_time) {
				vty_out(vty,
				"%% Value does not match with config\n");
				return CMD_SUCCESS;
			}
			bgp_vrf->evpn_info->dad_freeze = false;
		}
	}

	bgp_zebra_dup_addr_detection(bgp_vrf);

	return CMD_SUCCESS;
}

DEFPY(bgp_evpn_advertise_svi_ip,
      bgp_evpn_advertise_svi_ip_cmd,
      "[no$no] advertise-svi-ip",
      NO_STR
      "Advertise svi mac-ip routes in EVPN\n")
{
	struct bgp *bgp = VTY_GET_CONTEXT(bgp);

	if (!bgp)
		return CMD_WARNING;

	if (!EVPN_ENABLED(bgp)) {
		vty_out(vty,
			"This command is only supported under EVPN VRF\n");
		return CMD_WARNING;
	}

	if (no)
		evpn_set_advertise_svi_macip(bgp, NULL, 0);
	else
		evpn_set_advertise_svi_macip(bgp, NULL, 1);

	return CMD_SUCCESS;
}

DEFPY(bgp_evpn_advertise_svi_ip_vni,
      bgp_evpn_advertise_svi_ip_vni_cmd,
      "[no$no] advertise-svi-ip",
      NO_STR
      "Advertise svi mac-ip routes in EVPN for a VNI\n")
{
	struct bgp *bgp = VTY_GET_CONTEXT(bgp);
	VTY_DECLVAR_CONTEXT_SUB(bgpevpn, vpn);

	if (!bgp)
		return CMD_WARNING;

	if (no)
		evpn_set_advertise_svi_macip(bgp, vpn, 0);
	else
		evpn_set_advertise_svi_macip(bgp, vpn, 1);

	return CMD_SUCCESS;
}

DEFUN_HIDDEN (bgp_evpn_advertise_vni_subnet,
	      bgp_evpn_advertise_vni_subnet_cmd,
	      "advertise-subnet",
	      "Advertise the subnet corresponding to VNI\n")
{
	struct bgp *bgp_vrf = NULL;
	struct bgp *bgp = VTY_GET_CONTEXT(bgp);
	VTY_DECLVAR_CONTEXT_SUB(bgpevpn, vpn);

	if (!bgp)
		return CMD_WARNING;

	bgp_vrf = bgp_lookup_by_vrf_id(vpn->tenant_vrf_id);
	if (!bgp_vrf)
		return CMD_WARNING;

	evpn_set_advertise_subnet(bgp, vpn);
	return CMD_SUCCESS;
}

DEFUN_HIDDEN (no_bgp_evpn_advertise_vni_subnet,
	      no_bgp_evpn_advertise_vni_subnet_cmd,
	      "no advertise-subnet",
	      NO_STR
	      "Advertise All local VNIs\n")
{
	struct bgp *bgp = VTY_GET_CONTEXT(bgp);
	VTY_DECLVAR_CONTEXT_SUB(bgpevpn, vpn);

	if (!bgp)
		return CMD_WARNING;

	evpn_unset_advertise_subnet(bgp, vpn);
	return CMD_SUCCESS;
}

DEFUN (bgp_evpn_advertise_type5,
       bgp_evpn_advertise_type5_cmd,
       "advertise " BGP_AFI_CMD_STR "" BGP_SAFI_CMD_STR " [route-map WORD]",
       "Advertise prefix routes\n"
       BGP_AFI_HELP_STR
       BGP_SAFI_HELP_STR
       "route-map for filtering specific routes\n"
       "Name of the route map\n")
{
	struct bgp *bgp_vrf = VTY_GET_CONTEXT(bgp); /* bgp vrf instance */
	int idx_afi = 0;
	int idx_safi = 0;
	int idx_rmap = 0;
	afi_t afi = 0;
	safi_t safi = 0;
	int ret = 0;
	int rmap_changed = 0;

	argv_find_and_parse_afi(argv, argc, &idx_afi, &afi);
	argv_find_and_parse_safi(argv, argc, &idx_safi, &safi);
	ret = argv_find(argv, argc, "route-map", &idx_rmap);
	if (ret) {
		if (!bgp_vrf->adv_cmd_rmap[afi][safi].name)
			rmap_changed = 1;
		else if (strcmp(argv[idx_rmap + 1]->arg,
				bgp_vrf->adv_cmd_rmap[afi][safi].name)
			 != 0)
			rmap_changed = 1;
	} else if (bgp_vrf->adv_cmd_rmap[afi][safi].name) {
		rmap_changed = 1;
	}

	if (!(afi == AFI_IP || afi == AFI_IP6)) {
		vty_out(vty,
			"%%only ipv4 or ipv6 address families are supported");
		return CMD_WARNING;
	}

	if (safi != SAFI_UNICAST) {
		vty_out(vty,
			"%%only ipv4 unicast or ipv6 unicast are supported");
		return CMD_WARNING;
	}

	if (afi == AFI_IP) {

		/* if we are already advertising ipv4 prefix as type-5
		 * nothing to do
		 */
		if (!rmap_changed &&
		    CHECK_FLAG(bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
			       BGP_L2VPN_EVPN_ADVERTISE_IPV4_UNICAST))
			return CMD_WARNING;
		SET_FLAG(bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
			 BGP_L2VPN_EVPN_ADVERTISE_IPV4_UNICAST);
	} else {

		/* if we are already advertising ipv6 prefix as type-5
		 * nothing to do
		 */
		if (!rmap_changed &&
		    CHECK_FLAG(bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
			       BGP_L2VPN_EVPN_ADVERTISE_IPV6_UNICAST))
			return CMD_WARNING;
		SET_FLAG(bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
			 BGP_L2VPN_EVPN_ADVERTISE_IPV6_UNICAST);
	}

	if (rmap_changed) {
		bgp_evpn_withdraw_type5_routes(bgp_vrf, afi, safi);
		if (bgp_vrf->adv_cmd_rmap[afi][safi].name) {
			XFREE(MTYPE_ROUTE_MAP_NAME,
			      bgp_vrf->adv_cmd_rmap[afi][safi].name);
			route_map_counter_decrement(
					bgp_vrf->adv_cmd_rmap[afi][safi].map);
			bgp_vrf->adv_cmd_rmap[afi][safi].name = NULL;
			bgp_vrf->adv_cmd_rmap[afi][safi].map = NULL;
		}
	}

	/* set the route-map for advertise command */
	if (ret && argv[idx_rmap + 1]->arg) {
		bgp_vrf->adv_cmd_rmap[afi][safi].name =
			XSTRDUP(MTYPE_ROUTE_MAP_NAME, argv[idx_rmap + 1]->arg);
		bgp_vrf->adv_cmd_rmap[afi][safi].map =
			route_map_lookup_by_name(argv[idx_rmap + 1]->arg);
		route_map_counter_increment(
				bgp_vrf->adv_cmd_rmap[afi][safi].map);
	}

	/* advertise type-5 routes */
	if (advertise_type5_routes(bgp_vrf, afi))
		bgp_evpn_advertise_type5_routes(bgp_vrf, afi, safi);
	return CMD_SUCCESS;
}

DEFUN (no_bgp_evpn_advertise_type5,
       no_bgp_evpn_advertise_type5_cmd,
       "no advertise " BGP_AFI_CMD_STR "" BGP_SAFI_CMD_STR,
       NO_STR
       "Advertise prefix routes\n"
       BGP_AFI_HELP_STR
       BGP_SAFI_HELP_STR)
{
	struct bgp *bgp_vrf = VTY_GET_CONTEXT(bgp); /* bgp vrf instance */
	int idx_afi = 0;
	int idx_safi = 0;
	afi_t afi = 0;
	safi_t safi = 0;

	argv_find_and_parse_afi(argv, argc, &idx_afi, &afi);
	argv_find_and_parse_safi(argv, argc, &idx_safi, &safi);

	if (!(afi == AFI_IP || afi == AFI_IP6)) {
		vty_out(vty,
			"%%only ipv4 or ipv6 address families are supported");
		return CMD_WARNING;
	}

	if (safi != SAFI_UNICAST) {
		vty_out(vty,
			"%%only ipv4 unicast or ipv6 unicast are supported");
		return CMD_WARNING;
	}

	if (afi == AFI_IP) {

		/* if we are not advertising ipv4 prefix as type-5
		 * nothing to do
		 */
		if (CHECK_FLAG(bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
			       BGP_L2VPN_EVPN_ADVERTISE_IPV4_UNICAST)) {
			bgp_evpn_withdraw_type5_routes(bgp_vrf, afi, safi);
			UNSET_FLAG(bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
				   BGP_L2VPN_EVPN_ADVERTISE_IPV4_UNICAST);
		}
	} else {

		/* if we are not advertising ipv6 prefix as type-5
		 * nothing to do
		 */
		if (CHECK_FLAG(bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
			       BGP_L2VPN_EVPN_ADVERTISE_IPV6_UNICAST)) {
			bgp_evpn_withdraw_type5_routes(bgp_vrf, afi, safi);
			UNSET_FLAG(bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
				   BGP_L2VPN_EVPN_ADVERTISE_IPV6_UNICAST);
		}
	}

	/* clear the route-map information for advertise ipv4/ipv6 unicast */
	if (bgp_vrf->adv_cmd_rmap[afi][safi].name) {
		XFREE(MTYPE_ROUTE_MAP_NAME,
		      bgp_vrf->adv_cmd_rmap[afi][safi].name);
		bgp_vrf->adv_cmd_rmap[afi][safi].name = NULL;
		bgp_vrf->adv_cmd_rmap[afi][safi].map = NULL;
	}

	return CMD_SUCCESS;
}

/*
 * Display VNI information - for all or a specific VNI
 */
DEFUN(show_bgp_l2vpn_evpn_vni,
      show_bgp_l2vpn_evpn_vni_cmd,
      "show bgp l2vpn evpn vni [" CMD_VNI_RANGE "] [json]",
      SHOW_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "Show VNI\n"
      "VNI number\n"
      JSON_STR)
{
	struct bgp *bgp_evpn;
	vni_t vni;
	int idx = 0;
	bool uj = false;
	json_object *json = NULL;
	uint32_t num_l2vnis = 0;
	uint32_t num_l3vnis = 0;
	uint32_t num_vnis = 0;
	struct listnode *node = NULL;
	struct bgp *bgp_temp = NULL;

	uj = use_json(argc, argv);

	bgp_evpn = bgp_get_evpn();
	if (!bgp_evpn)
		return CMD_WARNING;

	if (!argv_find(argv, argc, "evpn", &idx))
		return CMD_WARNING;

	if (uj)
		json = json_object_new_object();

	if ((uj && argc == ((idx + 1) + 2)) || (!uj && argc == (idx + 1) + 1)) {

		num_l2vnis = hashcount(bgp_evpn->vnihash);

		for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp_temp)) {
			if (bgp_temp->l3vni)
				num_l3vnis++;
		}
		num_vnis = num_l2vnis + num_l3vnis;
		if (uj) {
			json_object_string_add(json, "advertiseGatewayMacip",
					       bgp_evpn->advertise_gw_macip
						       ? "Enabled"
						       : "Disabled");
			json_object_string_add(json, "advertiseSviMacip",
					bgp_evpn->evpn_info->advertise_svi_macip
					? "Enabled" : "Disabled");
			json_object_string_add(json, "advertiseAllVnis",
					       is_evpn_enabled() ? "Enabled"
								 : "Disabled");
			json_object_string_add(
				json, "flooding",
				bgp_evpn->vxlan_flood_ctrl
						== VXLAN_FLOOD_HEAD_END_REPL
					? "Head-end replication"
					: "Disabled");
			json_object_int_add(json, "numVnis", num_vnis);
			json_object_int_add(json, "numL2Vnis", num_l2vnis);
			json_object_int_add(json, "numL3Vnis", num_l3vnis);
		} else {
			vty_out(vty, "Advertise Gateway Macip: %s\n",
				bgp_evpn->advertise_gw_macip ? "Enabled"
							    : "Disabled");
			vty_out(vty, "Advertise SVI Macip: %s\n",
				bgp_evpn->evpn_info->advertise_svi_macip ? "Enabled"
							: "Disabled");
			vty_out(vty, "Advertise All VNI flag: %s\n",
				is_evpn_enabled() ? "Enabled" : "Disabled");
			vty_out(vty, "BUM flooding: %s\n",
				bgp_evpn->vxlan_flood_ctrl
						== VXLAN_FLOOD_HEAD_END_REPL
					? "Head-end replication"
					: "Disabled");
			vty_out(vty, "Number of L2 VNIs: %u\n", num_l2vnis);
			vty_out(vty, "Number of L3 VNIs: %u\n", num_l3vnis);
		}
		evpn_show_all_vnis(vty, bgp_evpn, json);
	} else {
		int vni_idx = 0;

		if (!argv_find(argv, argc, "vni", &vni_idx))
			return CMD_WARNING;

		/* Display specific VNI */
		vni = strtoul(argv[vni_idx + 1]->arg, NULL, 10);
		evpn_show_vni(vty, bgp_evpn, vni, json);
	}

	if (uj) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}

	return CMD_SUCCESS;
}

/* Disaply ES */
DEFUN(show_bgp_l2vpn_evpn_es,
      show_bgp_l2vpn_evpn_es_cmd,
      "show bgp l2vpn evpn es [ESI] [json]",
      SHOW_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "ethernet-Segment\n"
      "Ethernet-Segment Identifier\n"
      JSON_STR)
{
	int idx = 0;
	bool uj = false;
	esi_t esi;
	json_object *json = NULL;
	struct bgp *bgp = NULL;

	memset(&esi, 0, sizeof(esi));
	uj = use_json(argc, argv);

	bgp = bgp_get_evpn();
	if (!bgp)
		return CMD_WARNING;

	if (!argv_find(argv, argc, "evpn", &idx))
		return CMD_WARNING;

	if ((uj && argc == ((idx + 1) + 2)) ||
	    (!uj && argc == (idx + 1) + 1)) {

		/* show all ESs */
		evpn_show_all_es(vty, bgp, json);
	} else {

		/* show a specific ES */

		/* get the ESI - ESI-ID is at argv[5] */
		if (!str_to_esi(argv[idx + 2]->arg, &esi)) {
			vty_out(vty, "%% Malformed ESI\n");
			return CMD_WARNING;
		}
		evpn_show_es(vty, bgp, &esi, json);
	}

	if (uj) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}

	return CMD_SUCCESS;
}

/*
 * Display EVPN neighbor summary.
 */
DEFUN(show_bgp_l2vpn_evpn_summary,
      show_bgp_l2vpn_evpn_summary_cmd,
      "show bgp [vrf VRFNAME] l2vpn evpn summary [failed] [json]",
      SHOW_STR
      BGP_STR
      "bgp vrf\n"
      "vrf name\n"
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "Summary of BGP neighbor status\n"
      "Show only sessions not in Established state\n"
      JSON_STR)
{
	int idx_vrf = 0;
	bool uj = use_json(argc, argv);
	char *vrf = NULL;
	bool show_failed = false;

	if (argv_find(argv, argc, "vrf", &idx_vrf))
		vrf = argv[++idx_vrf]->arg;
	if (argv_find(argv, argc, "failed", &idx_vrf))
		show_failed = true;
	return bgp_show_summary_vty(vty, vrf, AFI_L2VPN, SAFI_EVPN,
				    show_failed, uj);
}

/*
 * Display global EVPN routing table.
 */
DEFUN(show_bgp_l2vpn_evpn_route,
      show_bgp_l2vpn_evpn_route_cmd,
      "show bgp l2vpn evpn route [detail] [type <macip|multicast|es|prefix>] [json]",
      SHOW_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "EVPN route information\n"
      "Display Detailed Information\n"
      "Specify Route type\n"
      "MAC-IP (Type-2) route\n"
      "Multicast (Type-3) route\n"
      "Ethernet Segment (type-4) route \n"
      "Prefix (type-5 )route\n"
      JSON_STR)
{
	struct bgp *bgp;
	int type_idx = 0;
	int detail = 0;
	int type = 0;
	bool uj = false;
	json_object *json = NULL;

	uj = use_json(argc, argv);

	bgp = bgp_get_evpn();
	if (!bgp)
		return CMD_WARNING;

	if (uj)
		json = json_object_new_object();

	/* get the type */
	if (argv_find(argv, argc, "type", &type_idx)) {
		/* Specific type is requested */
		if (strncmp(argv[type_idx + 1]->arg, "ma", 2) == 0)
			type = BGP_EVPN_MAC_IP_ROUTE;
		else if (strncmp(argv[type_idx + 1]->arg, "mu", 2) == 0)
			type = BGP_EVPN_IMET_ROUTE;
		else if (strncmp(argv[type_idx + 1]->arg, "e", 1) == 0)
			type = BGP_EVPN_ES_ROUTE;
		else if (strncmp(argv[type_idx + 1]->arg, "p", 1) == 0)
			type = BGP_EVPN_IP_PREFIX_ROUTE;
		else
			return CMD_WARNING;
	}

	if (argv_find(argv, argc, "detail", &detail))
		detail = 1;

	evpn_show_all_routes(vty, bgp, type, json, detail);

	if (uj) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}
	return CMD_SUCCESS;
}

/*
 * Display global EVPN routing table for specific RD.
 */
DEFUN(show_bgp_l2vpn_evpn_route_rd,
      show_bgp_l2vpn_evpn_route_rd_cmd,
      "show bgp l2vpn evpn route rd ASN:NN_OR_IP-ADDRESS:NN [type <macip|multicast|es|prefix>] [json]",
      SHOW_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "EVPN route information\n"
      "Route Distinguisher\n"
      "ASN:XX or A.B.C.D:XX\n"
      "Specify Route type\n"
      "MAC-IP (Type-2) route\n"
      "Multicast (Type-3) route\n"
      "Ethernet Segment route\n"
      "Prefix route\n"
      JSON_STR)
{
	struct bgp *bgp;
	int ret;
	struct prefix_rd prd;
	int type = 0;
	int rd_idx = 0;
	int type_idx = 0;
	bool uj = false;
	json_object *json = NULL;

	bgp = bgp_get_evpn();
	if (!bgp)
		return CMD_WARNING;

	/* check if we need json output */
	uj = use_json(argc, argv);
	if (uj)
		json = json_object_new_object();

	/* get the RD */
	if (argv_find(argv, argc, "rd", &rd_idx)) {
		ret = str2prefix_rd(argv[rd_idx + 1]->arg, &prd);

		if (!ret) {
			vty_out(vty, "%% Malformed Route Distinguisher\n");
			return CMD_WARNING;
		}
	}

	/* get the type */
	if (argv_find(argv, argc, "type", &type_idx)) {
		/* Specific type is requested */
		if (strncmp(argv[type_idx + 1]->arg, "ma", 2) == 0)
			type = BGP_EVPN_MAC_IP_ROUTE;
		else if (strncmp(argv[type_idx + 1]->arg, "mu", 2) == 0)
			type = BGP_EVPN_IMET_ROUTE;
		else if (strncmp(argv[type_idx + 1]->arg, "pr", 2) == 0)
			type = BGP_EVPN_IP_PREFIX_ROUTE;
		else
			return CMD_WARNING;
	}

	evpn_show_route_rd(vty, bgp, &prd, type, json);

	if (uj) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}

	return CMD_SUCCESS;
}

/*
 * Display global EVPN routing table for specific RD and MACIP.
 */
DEFUN(show_bgp_l2vpn_evpn_route_rd_macip,
      show_bgp_l2vpn_evpn_route_rd_macip_cmd,
      "show bgp l2vpn evpn route rd ASN:NN_OR_IP-ADDRESS:NN mac WORD [ip WORD] [json]",
      SHOW_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "EVPN route information\n"
      "Route Distinguisher\n"
      "ASN:XX or A.B.C.D:XX\n"
      "MAC\n"
      "MAC address (e.g., 00:e0:ec:20:12:62)\n"
      "IP\n"
      "IP address (IPv4 or IPv6)\n"
      JSON_STR)
{
	struct bgp *bgp;
	int ret;
	struct prefix_rd prd;
	struct ethaddr mac;
	struct ipaddr ip;
	int rd_idx = 0;
	int mac_idx = 0;
	int ip_idx = 0;
	bool uj = false;
	json_object *json = NULL;

	memset(&mac, 0, sizeof(struct ethaddr));
	memset(&ip, 0, sizeof(struct ipaddr));

	bgp = bgp_get_evpn();
	if (!bgp)
		return CMD_WARNING;

	/* check if we need json output */
	uj = use_json(argc, argv);
	if (uj)
		json = json_object_new_object();

	/* get the prd */
	if (argv_find(argv, argc, "rd", &rd_idx)) {
		ret = str2prefix_rd(argv[rd_idx + 1]->arg, &prd);
		if (!ret) {
			vty_out(vty, "%% Malformed Route Distinguisher\n");
			return CMD_WARNING;
		}
	}

	/* get the mac */
	if (argv_find(argv, argc, "mac", &mac_idx)) {
		if (!prefix_str2mac(argv[mac_idx + 1]->arg, &mac)) {
			vty_out(vty, "%% Malformed MAC address\n");
			return CMD_WARNING;
		}
	}

	/* get the ip if specified */
	if (argv_find(argv, argc, "ip", &ip_idx)) {
		if (str2ipaddr(argv[ip_idx + 1]->arg, &ip) != 0) {
			vty_out(vty, "%% Malformed IP address\n");
			return CMD_WARNING;
		}
	}

	evpn_show_route_rd_macip(vty, bgp, &prd, &mac, &ip, json);

	if (uj) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}

	return CMD_SUCCESS;
}

/* Display per ESI routing table */
DEFUN(show_bgp_l2vpn_evpn_route_esi,
      show_bgp_l2vpn_evpn_route_esi_cmd,
      "show bgp l2vpn evpn route esi ESI [json]",
      SHOW_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "EVPN route information\n"
      "Ethernet Segment Identifier\n"
      "ESI ID\n"
      JSON_STR)
{
	bool uj = false;
	esi_t esi;
	struct bgp *bgp = NULL;
	json_object *json = NULL;

	memset(&esi, 0, sizeof(esi));
	bgp = bgp_get_evpn();
	if (!bgp)
		return CMD_WARNING;

	uj = use_json(argc, argv);
	if (uj)
		json = json_object_new_object();

	/* get the ESI - ESI-ID is at argv[6] */
	if (!str_to_esi(argv[6]->arg, &esi)) {
		vty_out(vty, "%% Malformed ESI\n");
		return CMD_WARNING;
	}

	evpn_show_routes_esi(vty, bgp, &esi, json);

	if (uj) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}

	return CMD_SUCCESS;
}


/*
 * Display per-VNI EVPN routing table.
 */
DEFUN(show_bgp_l2vpn_evpn_route_vni, show_bgp_l2vpn_evpn_route_vni_cmd,
      "show bgp l2vpn evpn route vni " CMD_VNI_RANGE " [<type <macip|multicast> | vtep A.B.C.D>] [json]",
      SHOW_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "EVPN route information\n"
      "VXLAN Network Identifier\n"
      "VNI number\n"
      "Specify Route type\n"
      "MAC-IP (Type-2) route\n"
      "Multicast (Type-3) route\n"
      "Remote VTEP\n"
      "Remote VTEP IP address\n"
      JSON_STR)
{
	vni_t vni;
	struct bgp *bgp;
	struct in_addr vtep_ip;
	int type = 0;
	int idx = 0;
	bool uj = false;
	json_object *json = NULL;

	bgp = bgp_get_evpn();
	if (!bgp)
		return CMD_WARNING;

	/* check if we need json output */
	uj = use_json(argc, argv);
	if (uj)
		json = json_object_new_object();

	if (!argv_find(argv, argc, "evpn", &idx))
		return CMD_WARNING;

	vtep_ip.s_addr = 0;

	vni = strtoul(argv[idx + 3]->arg, NULL, 10);

	if ((!uj && ((argc == (idx + 1 + 5)) && argv[idx + 4]->arg))
	    || (uj && ((argc == (idx + 1 + 6)) && argv[idx + 4]->arg))) {
		if (strncmp(argv[idx + 4]->arg, "type", 4) == 0) {
			if (strncmp(argv[idx + 5]->arg, "ma", 2) == 0)
				type = BGP_EVPN_MAC_IP_ROUTE;
			else if (strncmp(argv[idx + 5]->arg, "mu", 2) == 0)
				type = BGP_EVPN_IMET_ROUTE;
			else
				return CMD_WARNING;
		} else if (strncmp(argv[idx + 4]->arg, "vtep", 4) == 0) {
			if (!inet_aton(argv[idx + 5]->arg, &vtep_ip)) {
				vty_out(vty, "%% Malformed VTEP IP address\n");
				return CMD_WARNING;
			}
		} else
			return CMD_WARNING;
	}

	evpn_show_routes_vni(vty, bgp, vni, type, vtep_ip, json);

	if (uj) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}

	return CMD_SUCCESS;
}

/*
 * Display per-VNI EVPN routing table for specific MACIP.
 */
DEFUN(show_bgp_l2vpn_evpn_route_vni_macip,
      show_bgp_l2vpn_evpn_route_vni_macip_cmd,
      "show bgp l2vpn evpn route vni " CMD_VNI_RANGE " mac WORD [ip WORD] [json]",
      SHOW_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "EVPN route information\n"
      "VXLAN Network Identifier\n"
      "VNI number\n"
      "MAC\n"
      "MAC address (e.g., 00:e0:ec:20:12:62)\n"
      "IP\n"
      "IP address (IPv4 or IPv6)\n"
      JSON_STR)
{
	vni_t vni;
	struct bgp *bgp;
	struct ethaddr mac;
	struct ipaddr ip;
	int idx = 0;
	bool uj = false;
	json_object *json = NULL;

	bgp = bgp_get_evpn();
	if (!bgp)
		return CMD_WARNING;

	/* check if we need json output */
	uj = use_json(argc, argv);
	if (uj)
		json = json_object_new_object();

	if (!argv_find(argv, argc, "evpn", &idx))
		return CMD_WARNING;

	/* get the VNI */
	vni = strtoul(argv[idx + 3]->arg, NULL, 10);

	/* get the mac */
	if (!prefix_str2mac(argv[idx + 5]->arg, &mac)) {
		vty_out(vty, "%% Malformed MAC address\n");
		return CMD_WARNING;
	}

	/* get the ip */
	memset(&ip, 0, sizeof(ip));
	if ((!uj && ((argc == (idx + 1 + 7)) && argv[idx + 7]->arg != NULL))
	    || (uj
		&& ((argc == (idx + 1 + 8)) && argv[idx + 7]->arg != NULL))) {
		if (str2ipaddr(argv[idx + 7]->arg, &ip) != 0) {
			vty_out(vty, "%% Malformed IP address\n");
			return CMD_WARNING;
		}
	}

	evpn_show_route_vni_macip(vty, bgp, vni, &mac, &ip, json);

	if (uj) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}

	return CMD_SUCCESS;
}

/*
 * Display per-VNI EVPN routing table for specific multicast IP (remote VTEP).
 */
DEFUN(show_bgp_l2vpn_evpn_route_vni_multicast,
      show_bgp_l2vpn_evpn_route_vni_multicast_cmd,
      "show bgp l2vpn evpn route vni " CMD_VNI_RANGE " multicast A.B.C.D [json]",
      SHOW_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "EVPN route information\n"
      "VXLAN Network Identifier\n"
      "VNI number\n"
      "Multicast (Type-3) route\n"
      "Originating Router IP address\n"
      JSON_STR)
{
	vni_t vni;
	struct bgp *bgp;
	int ret;
	struct in_addr orig_ip;
	int idx = 0;
	bool uj = false;
	json_object *json = NULL;

	bgp = bgp_get_evpn();
	if (!bgp)
		return CMD_WARNING;

	/* check if we need json output */
	uj = use_json(argc, argv);
	if (uj)
		json = json_object_new_object();

	if (!argv_find(argv, argc, "evpn", &idx))
		return CMD_WARNING;

	/* get the VNI */
	vni = strtoul(argv[idx + 3]->arg, NULL, 10);

	/* get the ip */
	ret = inet_aton(argv[idx + 5]->arg, &orig_ip);
	if (!ret) {
		vty_out(vty, "%% Malformed Originating Router IP address\n");
		return CMD_WARNING;
	}

	evpn_show_route_vni_multicast(vty, bgp, vni, orig_ip, json);

	if (uj) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}

	return CMD_SUCCESS;
}

/*
 * Display per-VNI EVPN routing table - for all VNIs.
 */
DEFUN(show_bgp_l2vpn_evpn_route_vni_all,
      show_bgp_l2vpn_evpn_route_vni_all_cmd,
      "show bgp l2vpn evpn route vni all [detail] [vtep A.B.C.D] [json]",
      SHOW_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "EVPN route information\n"
      "VXLAN Network Identifier\n"
      "All VNIs\n"
      "Print Detailed Output\n"
      "Remote VTEP\n"
      "Remote VTEP IP address\n"
      JSON_STR)
{
	struct bgp *bgp;
	struct in_addr vtep_ip;
	int idx = 0;
	bool uj = false;
	json_object *json = NULL;
	/* Detail Adjust. Adjust indexes according to detail option */
	int da = 0;

	bgp = bgp_get_evpn();
	if (!bgp)
		return CMD_WARNING;

	/* check if we need json output */
	uj = use_json(argc, argv);
	if (uj)
		json = json_object_new_object();

	if (!argv_find(argv, argc, "evpn", &idx))
		return CMD_WARNING;

	if (argv_find(argv, argc, "detail", &da))
		da = 1;

	/* vtep-ip position depends on detail option */
	vtep_ip.s_addr = 0;
	if ((!uj && (argc == (idx + 1 + 5 + da) && argv[idx + 5 + da]->arg))
	    || (uj
		&& (argc == (idx + 1 + 6 + da) && argv[idx + 5 + da]->arg))) {
		if (!inet_aton(argv[idx + 5 + da]->arg, &vtep_ip)) {
			vty_out(vty, "%% Malformed VTEP IP address\n");
			return CMD_WARNING;
		}
	}

	evpn_show_routes_vni_all(vty, bgp, vtep_ip, json, da);

	if (uj) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}

	return CMD_SUCCESS;
}

/*
 * Display EVPN import route-target hash table
 */
DEFUN(show_bgp_l2vpn_evpn_vrf_import_rt,
      show_bgp_l2vpn_evpn_vrf_import_rt_cmd,
      "show bgp l2vpn evpn vrf-import-rt [json]",
      SHOW_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "Show vrf import route target\n"
      JSON_STR)
{
	bool uj = false;
	struct bgp *bgp_evpn = NULL;
	json_object *json = NULL;

	bgp_evpn = bgp_get_evpn();
	if (!bgp_evpn)
		return CMD_WARNING;

	uj = use_json(argc, argv);
	if (uj)
		json = json_object_new_object();

	evpn_show_vrf_import_rts(vty, bgp_evpn, json);

	if (uj) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}

	return CMD_SUCCESS;
}

/*
 * Display EVPN import route-target hash table
 */
DEFUN(show_bgp_l2vpn_evpn_import_rt,
      show_bgp_l2vpn_evpn_import_rt_cmd,
      "show bgp l2vpn evpn import-rt [json]",
      SHOW_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "Show import route target\n"
      JSON_STR)
{
	struct bgp *bgp;
	bool uj = false;
	json_object *json = NULL;

	bgp = bgp_get_evpn();
	if (!bgp)
		return CMD_WARNING;

	uj = use_json(argc, argv);
	if (uj)
		json = json_object_new_object();

	evpn_show_import_rts(vty, bgp, json);

	if (uj) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}

	return CMD_SUCCESS;
}

DEFUN(test_adv_evpn_type4_route,
      test_adv_evpn_type4_route_cmd,
      "advertise es ESI",
      "Advertise EVPN ES route\n"
      "Ethernet-segment\n"
      "Ethernet-Segment Identifier\n")
{
	int ret = 0;
	esi_t esi;
	struct bgp *bgp;
	struct ipaddr vtep_ip;

	bgp = bgp_get_evpn();
	if (!bgp) {
		vty_out(vty, "%%EVPN BGP instance not yet created\n");
		return CMD_WARNING;
	}

	if (!str_to_esi(argv[2]->arg, &esi)) {
		vty_out(vty, "%%Malformed ESI\n");
		return CMD_WARNING;
	}

	vtep_ip.ipa_type = IPADDR_V4;
	vtep_ip.ipaddr_v4 = bgp->router_id;

	ret = bgp_evpn_local_es_add(bgp, &esi, &vtep_ip);
	if (ret == -1) {
		vty_out(vty, "%%Failed to EVPN advertise type-4 route\n");
		return CMD_WARNING;
	}
	return CMD_SUCCESS;
}

DEFUN(test_withdraw_evpn_type4_route,
      test_withdraw_evpn_type4_route_cmd,
      "withdraw es ESI",
      "Advertise EVPN ES route\n"
      "Ethernet-segment\n"
      "Ethernet-Segment Identifier\n")
{
	int ret = 0;
	esi_t esi;
	struct bgp *bgp;
	struct ipaddr vtep_ip;

	bgp = bgp_get_evpn();
	if (!bgp) {
		vty_out(vty, "%%EVPN BGP instance not yet created\n");
		return CMD_WARNING;
	}

	if (!bgp->peer_self) {
		vty_out(vty, "%%BGP instance doesn't have self peer\n");
		return CMD_WARNING;
	}

	if (!str_to_esi(argv[2]->arg, &esi)) {
		vty_out(vty, "%%Malformed ESI\n");
		return CMD_WARNING;
	}

	vtep_ip.ipa_type = IPADDR_V4;
	vtep_ip.ipaddr_v4 = bgp->router_id;
	ret = bgp_evpn_local_es_del(bgp, &esi, &vtep_ip);
	if (ret == -1) {
		vty_out(vty, "%%Failed to withdraw EVPN type-4 route\n");
		return CMD_WARNING;
	}
	return CMD_SUCCESS;
}

ALIAS_HIDDEN(show_bgp_l2vpn_evpn_vni, show_bgp_evpn_vni_cmd,
	     "show bgp evpn vni [" CMD_VNI_RANGE "]", SHOW_STR BGP_STR EVPN_HELP_STR
	     "Show VNI\n"
	     "VNI number\n")

ALIAS_HIDDEN(show_bgp_l2vpn_evpn_summary, show_bgp_evpn_summary_cmd,
	     "show bgp evpn summary [json]", SHOW_STR BGP_STR EVPN_HELP_STR
	     "Summary of BGP neighbor status\n" JSON_STR)

ALIAS_HIDDEN(show_bgp_l2vpn_evpn_route, show_bgp_evpn_route_cmd,
	     "show bgp evpn route [detail] [type <macip|multicast>]",
	     SHOW_STR BGP_STR EVPN_HELP_STR
	     "EVPN route information\n"
	     "Display Detailed Information\n"
	     "Specify Route type\n"
	     "MAC-IP (Type-2) route\n"
	     "Multicast (Type-3) route\n")

ALIAS_HIDDEN(
	show_bgp_l2vpn_evpn_route_rd, show_bgp_evpn_route_rd_cmd,
	"show bgp evpn route rd ASN:NN_OR_IP-ADDRESS:NN [type <macip|multicast>]",
	SHOW_STR BGP_STR EVPN_HELP_STR
	"EVPN route information\n"
	"Route Distinguisher\n"
	"ASN:XX or A.B.C.D:XX\n"
	"Specify Route type\n"
	"MAC-IP (Type-2) route\n"
	"Multicast (Type-3) route\n")

ALIAS_HIDDEN(
	show_bgp_l2vpn_evpn_route_rd_macip, show_bgp_evpn_route_rd_macip_cmd,
	"show bgp evpn route rd ASN:NN_OR_IP-ADDRESS:NN mac WORD [ip WORD]",
	SHOW_STR BGP_STR EVPN_HELP_STR
	"EVPN route information\n"
	"Route Distinguisher\n"
	"ASN:XX or A.B.C.D:XX\n"
	"MAC\n"
	"MAC address (e.g., 00:e0:ec:20:12:62)\n"
	"IP\n"
	"IP address (IPv4 or IPv6)\n")

ALIAS_HIDDEN(
	show_bgp_l2vpn_evpn_route_vni, show_bgp_evpn_route_vni_cmd,
	"show bgp evpn route vni " CMD_VNI_RANGE " [<type <macip|multicast> | vtep A.B.C.D>]",
	SHOW_STR BGP_STR EVPN_HELP_STR
	"EVPN route information\n"
	"VXLAN Network Identifier\n"
	"VNI number\n"
	"Specify Route type\n"
	"MAC-IP (Type-2) route\n"
	"Multicast (Type-3) route\n"
	"Remote VTEP\n"
	"Remote VTEP IP address\n")

ALIAS_HIDDEN(show_bgp_l2vpn_evpn_route_vni_macip,
	     show_bgp_evpn_route_vni_macip_cmd,
	     "show bgp evpn route vni " CMD_VNI_RANGE " mac WORD [ip WORD]",
	     SHOW_STR BGP_STR EVPN_HELP_STR
	     "EVPN route information\n"
	     "VXLAN Network Identifier\n"
	     "VNI number\n"
	     "MAC\n"
	     "MAC address (e.g., 00:e0:ec:20:12:62)\n"
	     "IP\n"
	     "IP address (IPv4 or IPv6)\n")

ALIAS_HIDDEN(show_bgp_l2vpn_evpn_route_vni_multicast,
	     show_bgp_evpn_route_vni_multicast_cmd,
	     "show bgp evpn route vni " CMD_VNI_RANGE " multicast A.B.C.D",
	     SHOW_STR BGP_STR EVPN_HELP_STR
	     "EVPN route information\n"
	     "VXLAN Network Identifier\n"
	     "VNI number\n"
	     "Multicast (Type-3) route\n"
	     "Originating Router IP address\n")

ALIAS_HIDDEN(show_bgp_l2vpn_evpn_route_vni_all, show_bgp_evpn_route_vni_all_cmd,
	     "show bgp evpn route vni all [detail] [vtep A.B.C.D]",
	     SHOW_STR BGP_STR EVPN_HELP_STR
	     "EVPN route information\n"
	     "VXLAN Network Identifier\n"
	     "All VNIs\n"
	     "Print Detailed Output\n"
	     "Remote VTEP\n"
	     "Remote VTEP IP address\n")

ALIAS_HIDDEN(show_bgp_l2vpn_evpn_import_rt, show_bgp_evpn_import_rt_cmd,
	     "show bgp evpn import-rt",
	     SHOW_STR BGP_STR EVPN_HELP_STR "Show import route target\n")

DEFUN_NOSH (bgp_evpn_vni,
            bgp_evpn_vni_cmd,
            "vni " CMD_VNI_RANGE,
            "VXLAN Network Identifier\n"
            "VNI number\n")
{
	vni_t vni;
	struct bgp *bgp = VTY_GET_CONTEXT(bgp);
	struct bgpevpn *vpn;

	if (!bgp)
		return CMD_WARNING;

	vni = strtoul(argv[1]->arg, NULL, 10);

	/* Create VNI, or mark as configured. */
	vpn = evpn_create_update_vni(bgp, vni);
	if (!vpn) {
		vty_out(vty, "%% Failed to create VNI \n");
		return CMD_WARNING;
	}

	VTY_PUSH_CONTEXT_SUB(BGP_EVPN_VNI_NODE, vpn);
	return CMD_SUCCESS;
}

DEFUN (no_bgp_evpn_vni,
       no_bgp_evpn_vni_cmd,
       "no vni " CMD_VNI_RANGE,
       NO_STR
       "VXLAN Network Identifier\n"
       "VNI number\n")
{
	vni_t vni;
	struct bgp *bgp = VTY_GET_CONTEXT(bgp);
	struct bgpevpn *vpn;

	if (!bgp)
		return CMD_WARNING;

	vni = strtoul(argv[2]->arg, NULL, 10);

	/* Check if we should disallow. */
	vpn = bgp_evpn_lookup_vni(bgp, vni);
	if (!vpn) {
		vty_out(vty, "%% Specified VNI does not exist\n");
		return CMD_WARNING;
	}
	if (!is_vni_configured(vpn)) {
		vty_out(vty, "%% Specified VNI is not configured\n");
		return CMD_WARNING;
	}

	evpn_delete_vni(bgp, vpn);
	return CMD_SUCCESS;
}

DEFUN_NOSH (exit_vni,
            exit_vni_cmd,
            "exit-vni",
            "Exit from VNI mode\n")
{
	if (vty->node == BGP_EVPN_VNI_NODE)
		vty->node = BGP_EVPN_NODE;
	return CMD_SUCCESS;
}

DEFUN (bgp_evpn_vrf_rd,
       bgp_evpn_vrf_rd_cmd,
       "rd ASN:NN_OR_IP-ADDRESS:NN",
       "Route Distinguisher\n"
       "ASN:XX or A.B.C.D:XX\n")
{
	int ret;
	struct prefix_rd prd;
	struct bgp *bgp_vrf = VTY_GET_CONTEXT(bgp);

	if (!bgp_vrf)
		return CMD_WARNING;

	ret = str2prefix_rd(argv[1]->arg, &prd);
	if (!ret) {
		vty_out(vty, "%% Malformed Route Distinguisher\n");
		return CMD_WARNING;
	}

	/* If same as existing value, there is nothing more to do. */
	if (bgp_evpn_vrf_rd_matches_existing(bgp_vrf, &prd))
		return CMD_SUCCESS;

	/* Configure or update the RD. */
	evpn_configure_vrf_rd(bgp_vrf, &prd);
	return CMD_SUCCESS;
}

DEFUN (no_bgp_evpn_vrf_rd,
       no_bgp_evpn_vrf_rd_cmd,
       "no rd ASN:NN_OR_IP-ADDRESS:NN",
       NO_STR
       "Route Distinguisher\n"
       "ASN:XX or A.B.C.D:XX\n")
{
	int ret;
	struct prefix_rd prd;
	struct bgp *bgp_vrf = VTY_GET_CONTEXT(bgp);

	if (!bgp_vrf)
		return CMD_WARNING;

	ret = str2prefix_rd(argv[2]->arg, &prd);
	if (!ret) {
		vty_out(vty, "%% Malformed Route Distinguisher\n");
		return CMD_WARNING;
	}

	/* Check if we should disallow. */
	if (!is_vrf_rd_configured(bgp_vrf)) {
		vty_out(vty, "%% RD is not configured for this VRF\n");
		return CMD_WARNING;
	}

	if (!bgp_evpn_vrf_rd_matches_existing(bgp_vrf, &prd)) {
		vty_out(vty,
			"%% RD specified does not match configuration for this VRF\n");
		return CMD_WARNING;
	}

	evpn_unconfigure_vrf_rd(bgp_vrf);
	return CMD_SUCCESS;
}

DEFUN (no_bgp_evpn_vrf_rd_without_val,
       no_bgp_evpn_vrf_rd_without_val_cmd,
       "no rd",
       NO_STR
       "Route Distinguisher\n")
{
	struct bgp *bgp_vrf = VTY_GET_CONTEXT(bgp);

	if (!bgp_vrf)
		return CMD_WARNING;

	/* Check if we should disallow. */
	if (!is_vrf_rd_configured(bgp_vrf)) {
		vty_out(vty, "%% RD is not configured for this VRF\n");
		return CMD_WARNING;
	}

	evpn_unconfigure_vrf_rd(bgp_vrf);
	return CMD_SUCCESS;
}

DEFUN (bgp_evpn_vni_rd,
       bgp_evpn_vni_rd_cmd,
       "rd ASN:NN_OR_IP-ADDRESS:NN",
       "Route Distinguisher\n"
       "ASN:XX or A.B.C.D:XX\n")
{
	struct prefix_rd prd;
	struct bgp *bgp = VTY_GET_CONTEXT(bgp);
	VTY_DECLVAR_CONTEXT_SUB(bgpevpn, vpn);
	int ret;

	if (!bgp)
		return CMD_WARNING;

	if (!EVPN_ENABLED(bgp)) {
		vty_out(vty,
			"This command is only supported under EVPN VRF\n");
		return CMD_WARNING;
	}

	ret = str2prefix_rd(argv[1]->arg, &prd);
	if (!ret) {
		vty_out(vty, "%% Malformed Route Distinguisher\n");
		return CMD_WARNING;
	}

	/* If same as existing value, there is nothing more to do. */
	if (bgp_evpn_rd_matches_existing(vpn, &prd))
		return CMD_SUCCESS;

	/* Configure or update the RD. */
	evpn_configure_rd(bgp, vpn, &prd);
	return CMD_SUCCESS;
}

DEFUN (no_bgp_evpn_vni_rd,
       no_bgp_evpn_vni_rd_cmd,
       "no rd ASN:NN_OR_IP-ADDRESS:NN",
       NO_STR
       "Route Distinguisher\n"
       "ASN:XX or A.B.C.D:XX\n")
{
	struct prefix_rd prd;
	struct bgp *bgp = VTY_GET_CONTEXT(bgp);
	VTY_DECLVAR_CONTEXT_SUB(bgpevpn, vpn);
	int ret;

	if (!bgp)
		return CMD_WARNING;

	if (!EVPN_ENABLED(bgp)) {
		vty_out(vty,
			"This command is only supported under EVPN VRF\n");
		return CMD_WARNING;
	}

	ret = str2prefix_rd(argv[2]->arg, &prd);
	if (!ret) {
		vty_out(vty, "%% Malformed Route Distinguisher\n");
		return CMD_WARNING;
	}

	/* Check if we should disallow. */
	if (!is_rd_configured(vpn)) {
		vty_out(vty, "%% RD is not configured for this VNI\n");
		return CMD_WARNING;
	}

	if (!bgp_evpn_rd_matches_existing(vpn, &prd)) {
		vty_out(vty,
			"%% RD specified does not match configuration for this VNI\n");
		return CMD_WARNING;
	}

	evpn_unconfigure_rd(bgp, vpn);
	return CMD_SUCCESS;
}

DEFUN (no_bgp_evpn_vni_rd_without_val,
       no_bgp_evpn_vni_rd_without_val_cmd,
       "no rd",
       NO_STR
       "Route Distinguisher\n")
{
	struct bgp *bgp = VTY_GET_CONTEXT(bgp);
	VTY_DECLVAR_CONTEXT_SUB(bgpevpn, vpn);

	if (!bgp)
		return CMD_WARNING;

	if (!EVPN_ENABLED(bgp)) {
		vty_out(vty,
			"This command is only supported under EVPN VRF\n");
		return CMD_WARNING;
	}

	/* Check if we should disallow. */
	if (!is_rd_configured(vpn)) {
		vty_out(vty, "%% RD is not configured for this VNI\n");
		return CMD_WARNING;
	}

	evpn_unconfigure_rd(bgp, vpn);
	return CMD_SUCCESS;
}

/*
 * Loop over all extended-communities in the route-target list rtl and
 * return 1 if we find ecomtarget
 */
static int bgp_evpn_rt_matches_existing(struct list *rtl,
					struct ecommunity *ecomtarget)
{
	struct listnode *node, *nnode;
	struct ecommunity *ecom;

	for (ALL_LIST_ELEMENTS(rtl, node, nnode, ecom)) {
		if (ecommunity_match(ecom, ecomtarget))
			return 1;
	}

	return 0;
}

/* display L3VNI related info for a VRF instance */
DEFUN (show_bgp_vrf_l3vni_info,
       show_bgp_vrf_l3vni_info_cmd,
       "show bgp vrf VRFNAME vni [json]",
       SHOW_STR
       BGP_STR
       "show bgp vrf\n"
       "VRF Name\n"
       "L3-VNI\n"
       JSON_STR)
{
	char buf[ETHER_ADDR_STRLEN];
	char buf1[INET6_ADDRSTRLEN];
	int idx_vrf = 3;
	const char *name = NULL;
	struct bgp *bgp = NULL;
	struct listnode *node = NULL;
	struct bgpevpn *vpn = NULL;
	struct ecommunity *ecom = NULL;
	json_object *json = NULL;
	json_object *json_vnis = NULL;
	json_object *json_export_rts = NULL;
	json_object *json_import_rts = NULL;
	bool uj = use_json(argc, argv);

	if (uj) {
		json = json_object_new_object();
		json_vnis = json_object_new_array();
		json_export_rts = json_object_new_array();
		json_import_rts = json_object_new_array();
	}

	name = argv[idx_vrf]->arg;
	bgp = bgp_lookup_by_name(name);
	if (!bgp) {
		if (!uj)
			vty_out(vty, "BGP instance for VRF %s not found", name);
		else {
			json_object_string_add(json, "warning",
					       "BGP instance not found");
			vty_out(vty, "%s\n", json_object_to_json_string(json));
			json_object_free(json);
		}
		return CMD_WARNING;
	}

	if (!json) {
		vty_out(vty, "BGP VRF: %s\n", name);
		vty_out(vty, "  Local-Ip: %s\n", inet_ntoa(bgp->originator_ip));
		vty_out(vty, "  L3-VNI: %u\n", bgp->l3vni);
		vty_out(vty, "  Rmac: %s\n",
			prefix_mac2str(&bgp->rmac, buf, sizeof(buf)));
		vty_out(vty, "  VNI Filter: %s\n",
			CHECK_FLAG(bgp->vrf_flags,
				   BGP_VRF_L3VNI_PREFIX_ROUTES_ONLY)
				? "prefix-routes-only"
				: "none");
		vty_out(vty, "  L2-VNI List:\n");
		vty_out(vty, "    ");
		for (ALL_LIST_ELEMENTS_RO(bgp->l2vnis, node, vpn))
			vty_out(vty, "%u  ", vpn->vni);
		vty_out(vty, "\n");
		vty_out(vty, "  Export-RTs:\n");
		vty_out(vty, "    ");
		for (ALL_LIST_ELEMENTS_RO(bgp->vrf_export_rtl, node, ecom))
			vty_out(vty, "%s  ", ecommunity_str(ecom));
		vty_out(vty, "\n");
		vty_out(vty, "  Import-RTs:\n");
		vty_out(vty, "    ");
		for (ALL_LIST_ELEMENTS_RO(bgp->vrf_import_rtl, node, ecom))
			vty_out(vty, "%s  ", ecommunity_str(ecom));
		vty_out(vty, "\n");
		vty_out(vty, "  RD: %s\n",
			prefix_rd2str(&bgp->vrf_prd, buf1, RD_ADDRSTRLEN));
	} else {
		json_object_string_add(json, "vrf", name);
		json_object_string_add(json, "local-ip",
				       inet_ntoa(bgp->originator_ip));
		json_object_int_add(json, "l3vni", bgp->l3vni);
		json_object_string_add(
			json, "rmac",
			prefix_mac2str(&bgp->rmac, buf, sizeof(buf)));
		json_object_string_add(
			json, "vniFilter",
			CHECK_FLAG(bgp->vrf_flags,
				   BGP_VRF_L3VNI_PREFIX_ROUTES_ONLY)
				? "prefix-routes-only"
				: "none");
		/* list of l2vnis */
		for (ALL_LIST_ELEMENTS_RO(bgp->l2vnis, node, vpn))
			json_object_array_add(json_vnis,
					      json_object_new_int(vpn->vni));
		json_object_object_add(json, "l2vnis", json_vnis);

		/* export rts */
		for (ALL_LIST_ELEMENTS_RO(bgp->vrf_export_rtl, node, ecom))
			json_object_array_add(
				json_export_rts,
				json_object_new_string(ecommunity_str(ecom)));
		json_object_object_add(json, "export-rts", json_export_rts);

		/* import rts */
		for (ALL_LIST_ELEMENTS_RO(bgp->vrf_import_rtl, node, ecom))
			json_object_array_add(
				json_import_rts,
				json_object_new_string(ecommunity_str(ecom)));
		json_object_object_add(json, "import-rts", json_import_rts);
		json_object_string_add(
			json, "rd",
			prefix_rd2str(&bgp->vrf_prd, buf1, RD_ADDRSTRLEN));
	}

	if (uj) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}
	return CMD_SUCCESS;
}

/* import/export rt for l3vni-vrf */
DEFUN (bgp_evpn_vrf_rt,
       bgp_evpn_vrf_rt_cmd,
       "route-target <both|import|export> RT",
       "Route Target\n"
       "import and export\n"
       "import\n"
       "export\n"
       "Route target (A.B.C.D:MN|EF:OPQR|GHJK:MN)\n")
{
	int rt_type;
	struct bgp *bgp = VTY_GET_CONTEXT(bgp);
	struct ecommunity *ecomadd = NULL;

	if (!bgp)
		return CMD_WARNING;

	if (!strcmp(argv[1]->arg, "import"))
		rt_type = RT_TYPE_IMPORT;
	else if (!strcmp(argv[1]->arg, "export"))
		rt_type = RT_TYPE_EXPORT;
	else if (!strcmp(argv[1]->arg, "both"))
		rt_type = RT_TYPE_BOTH;
	else {
		vty_out(vty, "%% Invalid Route Target type\n");
		return CMD_WARNING;
	}

	/* Add/update the import route-target */
	if (rt_type == RT_TYPE_BOTH || rt_type == RT_TYPE_IMPORT) {
		ecomadd = ecommunity_str2com(argv[2]->arg,
					     ECOMMUNITY_ROUTE_TARGET, 0);
		if (!ecomadd) {
			vty_out(vty, "%% Malformed Route Target list\n");
			return CMD_WARNING;
		}
		ecommunity_str(ecomadd);

		/* Do nothing if we already have this import route-target */
		if (!bgp_evpn_rt_matches_existing(bgp->vrf_import_rtl, ecomadd))
			bgp_evpn_configure_import_rt_for_vrf(bgp, ecomadd);
	}

	/* Add/update the export route-target */
	if (rt_type == RT_TYPE_BOTH || rt_type == RT_TYPE_EXPORT) {
		ecomadd = ecommunity_str2com(argv[2]->arg,
					     ECOMMUNITY_ROUTE_TARGET, 0);
		if (!ecomadd) {
			vty_out(vty, "%% Malformed Route Target list\n");
			return CMD_WARNING;
		}
		ecommunity_str(ecomadd);

		/* Do nothing if we already have this export route-target */
		if (!bgp_evpn_rt_matches_existing(bgp->vrf_export_rtl, ecomadd))
			bgp_evpn_configure_export_rt_for_vrf(bgp, ecomadd);
	}

	return CMD_SUCCESS;
}

DEFUN (no_bgp_evpn_vrf_rt,
       no_bgp_evpn_vrf_rt_cmd,
       "no route-target <both|import|export> RT",
       NO_STR
       "Route Target\n"
       "import and export\n"
       "import\n"
       "export\n"
       "ASN:XX or A.B.C.D:XX\n")
{
	struct bgp *bgp = VTY_GET_CONTEXT(bgp);
	int rt_type, found_ecomdel;
	struct ecommunity *ecomdel = NULL;

	if (!bgp)
		return CMD_WARNING;

	if (!strcmp(argv[2]->arg, "import"))
		rt_type = RT_TYPE_IMPORT;
	else if (!strcmp(argv[2]->arg, "export"))
		rt_type = RT_TYPE_EXPORT;
	else if (!strcmp(argv[2]->arg, "both"))
		rt_type = RT_TYPE_BOTH;
	else {
		vty_out(vty, "%% Invalid Route Target type\n");
		return CMD_WARNING;
	}

	if (rt_type == RT_TYPE_IMPORT) {
		if (!CHECK_FLAG(bgp->vrf_flags, BGP_VRF_IMPORT_RT_CFGD)) {
			vty_out(vty,
				"%% Import RT is not configured for this VRF\n");
			return CMD_WARNING;
		}
	} else if (rt_type == RT_TYPE_EXPORT) {
		if (!CHECK_FLAG(bgp->vrf_flags, BGP_VRF_EXPORT_RT_CFGD)) {
			vty_out(vty,
				"%% Export RT is not configured for this VRF\n");
			return CMD_WARNING;
		}
	} else if (rt_type == RT_TYPE_BOTH) {
		if (!CHECK_FLAG(bgp->vrf_flags, BGP_VRF_IMPORT_RT_CFGD)
		    && !CHECK_FLAG(bgp->vrf_flags, BGP_VRF_EXPORT_RT_CFGD)) {
			vty_out(vty,
				"%% Import/Export RT is not configured for this VRF\n");
			return CMD_WARNING;
		}
	}

	ecomdel = ecommunity_str2com(argv[3]->arg, ECOMMUNITY_ROUTE_TARGET, 0);
	if (!ecomdel) {
		vty_out(vty, "%% Malformed Route Target list\n");
		return CMD_WARNING;
	}
	ecommunity_str(ecomdel);

	if (rt_type == RT_TYPE_IMPORT) {
		if (!bgp_evpn_rt_matches_existing(bgp->vrf_import_rtl,
						  ecomdel)) {
			vty_out(vty,
				"%% RT specified does not match configuration for this VRF\n");
			return CMD_WARNING;
		}
		bgp_evpn_unconfigure_import_rt_for_vrf(bgp, ecomdel);
	} else if (rt_type == RT_TYPE_EXPORT) {
		if (!bgp_evpn_rt_matches_existing(bgp->vrf_export_rtl,
						  ecomdel)) {
			vty_out(vty,
				"%% RT specified does not match configuration for this VRF\n");
			return CMD_WARNING;
		}
		bgp_evpn_unconfigure_export_rt_for_vrf(bgp, ecomdel);
	} else if (rt_type == RT_TYPE_BOTH) {
		found_ecomdel = 0;

		if (bgp_evpn_rt_matches_existing(bgp->vrf_import_rtl,
						 ecomdel)) {
			bgp_evpn_unconfigure_import_rt_for_vrf(bgp, ecomdel);
			found_ecomdel = 1;
		}

		if (bgp_evpn_rt_matches_existing(bgp->vrf_export_rtl,
						 ecomdel)) {
			bgp_evpn_unconfigure_export_rt_for_vrf(bgp, ecomdel);
			found_ecomdel = 1;
		}

		if (!found_ecomdel) {
			vty_out(vty,
				"%% RT specified does not match configuration for this VRF\n");
			return CMD_WARNING;
		}
	}

	return CMD_SUCCESS;
}

DEFUN (bgp_evpn_vni_rt,
       bgp_evpn_vni_rt_cmd,
       "route-target <both|import|export> RT",
       "Route Target\n"
       "import and export\n"
       "import\n"
       "export\n"
       "Route target (A.B.C.D:MN|EF:OPQR|GHJK:MN)\n")
{
	struct bgp *bgp = VTY_GET_CONTEXT(bgp);
	VTY_DECLVAR_CONTEXT_SUB(bgpevpn, vpn);
	int rt_type;
	struct ecommunity *ecomadd = NULL;

	if (!bgp)
		return CMD_WARNING;

	if (!EVPN_ENABLED(bgp)) {
		vty_out(vty,
			"This command is only supported under EVPN VRF\n");
		return CMD_WARNING;
	}

	if (!strcmp(argv[1]->text, "import"))
		rt_type = RT_TYPE_IMPORT;
	else if (!strcmp(argv[1]->text, "export"))
		rt_type = RT_TYPE_EXPORT;
	else if (!strcmp(argv[1]->text, "both"))
		rt_type = RT_TYPE_BOTH;
	else {
		vty_out(vty, "%% Invalid Route Target type\n");
		return CMD_WARNING;
	}

	/* Add/update the import route-target */
	if (rt_type == RT_TYPE_BOTH || rt_type == RT_TYPE_IMPORT) {
		ecomadd = ecommunity_str2com(argv[2]->arg,
					     ECOMMUNITY_ROUTE_TARGET, 0);
		if (!ecomadd) {
			vty_out(vty, "%% Malformed Route Target list\n");
			return CMD_WARNING;
		}
		ecommunity_str(ecomadd);

		/* Do nothing if we already have this import route-target */
		if (!bgp_evpn_rt_matches_existing(vpn->import_rtl, ecomadd))
			evpn_configure_import_rt(bgp, vpn, ecomadd);
	}

	/* Add/update the export route-target */
	if (rt_type == RT_TYPE_BOTH || rt_type == RT_TYPE_EXPORT) {
		ecomadd = ecommunity_str2com(argv[2]->arg,
					     ECOMMUNITY_ROUTE_TARGET, 0);
		if (!ecomadd) {
			vty_out(vty, "%% Malformed Route Target list\n");
			return CMD_WARNING;
		}
		ecommunity_str(ecomadd);

		/* Do nothing if we already have this export route-target */
		if (!bgp_evpn_rt_matches_existing(vpn->export_rtl, ecomadd))
			evpn_configure_export_rt(bgp, vpn, ecomadd);
	}

	return CMD_SUCCESS;
}

DEFUN (no_bgp_evpn_vni_rt,
       no_bgp_evpn_vni_rt_cmd,
       "no route-target <both|import|export> RT",
       NO_STR
       "Route Target\n"
       "import and export\n"
       "import\n"
       "export\n"
       "ASN:XX or A.B.C.D:XX\n")
{
	struct bgp *bgp = VTY_GET_CONTEXT(bgp);
	VTY_DECLVAR_CONTEXT_SUB(bgpevpn, vpn);
	int rt_type, found_ecomdel;
	struct ecommunity *ecomdel = NULL;

	if (!bgp)
		return CMD_WARNING;

	if (!EVPN_ENABLED(bgp)) {
		vty_out(vty,
			"This command is only supported under EVPN VRF\n");
		return CMD_WARNING;
	}

	if (!strcmp(argv[2]->text, "import"))
		rt_type = RT_TYPE_IMPORT;
	else if (!strcmp(argv[2]->text, "export"))
		rt_type = RT_TYPE_EXPORT;
	else if (!strcmp(argv[2]->text, "both"))
		rt_type = RT_TYPE_BOTH;
	else {
		vty_out(vty, "%% Invalid Route Target type\n");
		return CMD_WARNING;
	}

	/* The user did "no route-target import", check to see if there are any
	 * import route-targets configured. */
	if (rt_type == RT_TYPE_IMPORT) {
		if (!is_import_rt_configured(vpn)) {
			vty_out(vty,
				"%% Import RT is not configured for this VNI\n");
			return CMD_WARNING;
		}
	} else if (rt_type == RT_TYPE_EXPORT) {
		if (!is_export_rt_configured(vpn)) {
			vty_out(vty,
				"%% Export RT is not configured for this VNI\n");
			return CMD_WARNING;
		}
	} else if (rt_type == RT_TYPE_BOTH) {
		if (!is_import_rt_configured(vpn)
		    && !is_export_rt_configured(vpn)) {
			vty_out(vty,
				"%% Import/Export RT is not configured for this VNI\n");
			return CMD_WARNING;
		}
	}

	ecomdel = ecommunity_str2com(argv[3]->arg, ECOMMUNITY_ROUTE_TARGET, 0);
	if (!ecomdel) {
		vty_out(vty, "%% Malformed Route Target list\n");
		return CMD_WARNING;
	}
	ecommunity_str(ecomdel);

	if (rt_type == RT_TYPE_IMPORT) {
		if (!bgp_evpn_rt_matches_existing(vpn->import_rtl, ecomdel)) {
			vty_out(vty,
				"%% RT specified does not match configuration for this VNI\n");
			return CMD_WARNING;
		}
		evpn_unconfigure_import_rt(bgp, vpn, ecomdel);
	} else if (rt_type == RT_TYPE_EXPORT) {
		if (!bgp_evpn_rt_matches_existing(vpn->export_rtl, ecomdel)) {
			vty_out(vty,
				"%% RT specified does not match configuration for this VNI\n");
			return CMD_WARNING;
		}
		evpn_unconfigure_export_rt(bgp, vpn, ecomdel);
	} else if (rt_type == RT_TYPE_BOTH) {
		found_ecomdel = 0;

		if (bgp_evpn_rt_matches_existing(vpn->import_rtl, ecomdel)) {
			evpn_unconfigure_import_rt(bgp, vpn, ecomdel);
			found_ecomdel = 1;
		}

		if (bgp_evpn_rt_matches_existing(vpn->export_rtl, ecomdel)) {
			evpn_unconfigure_export_rt(bgp, vpn, ecomdel);
			found_ecomdel = 1;
		}

		if (!found_ecomdel) {
			vty_out(vty,
				"%% RT specified does not match configuration for this VNI\n");
			return CMD_WARNING;
		}
	}

	return CMD_SUCCESS;
}

DEFUN (no_bgp_evpn_vni_rt_without_val,
       no_bgp_evpn_vni_rt_without_val_cmd,
       "no route-target <import|export>",
       NO_STR
       "Route Target\n"
       "import\n"
       "export\n")
{
	struct bgp *bgp = VTY_GET_CONTEXT(bgp);
	VTY_DECLVAR_CONTEXT_SUB(bgpevpn, vpn);
	int rt_type;

	if (!bgp)
		return CMD_WARNING;

	if (!EVPN_ENABLED(bgp)) {
		vty_out(vty,
			"This command is only supported under EVPN VRF\n");
		return CMD_WARNING;
	}

	if (!strcmp(argv[2]->text, "import")) {
		rt_type = RT_TYPE_IMPORT;
	} else if (!strcmp(argv[2]->text, "export")) {
		rt_type = RT_TYPE_EXPORT;
	} else {
		vty_out(vty, "%% Invalid Route Target type\n");
		return CMD_WARNING;
	}

	/* Check if we should disallow. */
	if (rt_type == RT_TYPE_IMPORT) {
		if (!is_import_rt_configured(vpn)) {
			vty_out(vty,
				"%% Import RT is not configured for this VNI\n");
			return CMD_WARNING;
		}
	} else {
		if (!is_export_rt_configured(vpn)) {
			vty_out(vty,
				"%% Export RT is not configured for this VNI\n");
			return CMD_WARNING;
		}
	}

	/* Unconfigure the RT. */
	if (rt_type == RT_TYPE_IMPORT)
		evpn_unconfigure_import_rt(bgp, vpn, NULL);
	else
		evpn_unconfigure_export_rt(bgp, vpn, NULL);
	return CMD_SUCCESS;
}

static int vni_cmp(const void **a, const void **b)
{
	const struct bgpevpn *first = *a;
	const struct bgpevpn *secnd = *b;

	return secnd->vni - first->vni;
}

/*
 * Output EVPN configuration information.
 */
void bgp_config_write_evpn_info(struct vty *vty, struct bgp *bgp, afi_t afi,
				safi_t safi)
{
	char buf1[RD_ADDRSTRLEN];

	if (bgp->vnihash) {
		struct list *vnilist = hash_to_list(bgp->vnihash);
		struct listnode *ln;
		struct bgpevpn *data;

		list_sort(vnilist, vni_cmp);
		for (ALL_LIST_ELEMENTS_RO(vnilist, ln, data))
			write_vni_config(vty, data);

		list_delete(&vnilist);
	}

	if (bgp->advertise_all_vni)
		vty_out(vty, "  advertise-all-vni\n");

	if (bgp->advertise_autort_rfc8365)
		vty_out(vty, "  autort rfc8365-compatible\n");

	if (bgp->advertise_gw_macip)
		vty_out(vty, "  advertise-default-gw\n");

	if (bgp->evpn_info->advertise_svi_macip)
		vty_out(vty, "  advertise-svi-ip\n");

	if (!bgp->evpn_info->dup_addr_detect)
		vty_out(vty, "  no dup-addr-detection\n");

	if (bgp->evpn_info->dad_max_moves !=
		EVPN_DAD_DEFAULT_MAX_MOVES ||
		bgp->evpn_info->dad_time != EVPN_DAD_DEFAULT_TIME)
		vty_out(vty, "  dup-addr-detection max-moves %u time %u\n",
			bgp->evpn_info->dad_max_moves,
			bgp->evpn_info->dad_time);

	if (bgp->evpn_info->dad_freeze) {
		if (bgp->evpn_info->dad_freeze_time)
			vty_out(vty,
				"  dup-addr-detection freeze %u\n",
				bgp->evpn_info->dad_freeze_time);
		else
			vty_out(vty,
				"  dup-addr-detection freeze permanent\n");
	}

	if (bgp->vxlan_flood_ctrl == VXLAN_FLOOD_DISABLED)
		vty_out(vty, "  flooding disable\n");

	if (CHECK_FLAG(bgp->af_flags[AFI_L2VPN][SAFI_EVPN],
		       BGP_L2VPN_EVPN_ADVERTISE_IPV4_UNICAST)) {
		if (bgp->adv_cmd_rmap[AFI_IP][SAFI_UNICAST].name)
			vty_out(vty, "  advertise ipv4 unicast route-map %s\n",
				bgp->adv_cmd_rmap[AFI_IP][SAFI_UNICAST].name);
		else
			vty_out(vty, "  advertise ipv4 unicast\n");
	}

	if (CHECK_FLAG(bgp->af_flags[AFI_L2VPN][SAFI_EVPN],
		       BGP_L2VPN_EVPN_ADVERTISE_IPV6_UNICAST)) {
		if (bgp->adv_cmd_rmap[AFI_IP6][SAFI_UNICAST].name)
			vty_out(vty, "  advertise ipv6 unicast route-map %s\n",
				bgp->adv_cmd_rmap[AFI_IP6][SAFI_UNICAST].name);
		else
			vty_out(vty, "  advertise ipv6 unicast\n");
	}

	if (CHECK_FLAG(bgp->af_flags[AFI_L2VPN][SAFI_EVPN],
		       BGP_L2VPN_EVPN_DEFAULT_ORIGINATE_IPV4))
		vty_out(vty, "  default-originate ipv4\n");

	if (CHECK_FLAG(bgp->af_flags[AFI_L2VPN][SAFI_EVPN],
		       BGP_L2VPN_EVPN_DEFAULT_ORIGINATE_IPV6))
		vty_out(vty, "  default-originate ipv6\n");

	if (CHECK_FLAG(bgp->vrf_flags, BGP_VRF_RD_CFGD))
		vty_out(vty, "  rd %s\n",
			prefix_rd2str(&bgp->vrf_prd, buf1, sizeof(buf1)));

	/* import route-target */
	if (CHECK_FLAG(bgp->vrf_flags, BGP_VRF_IMPORT_RT_CFGD)) {
		char *ecom_str;
		struct listnode *node, *nnode;
		struct ecommunity *ecom;

		for (ALL_LIST_ELEMENTS(bgp->vrf_import_rtl, node, nnode,
				       ecom)) {
			ecom_str = ecommunity_ecom2str(
				ecom, ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
			vty_out(vty, "  route-target import %s\n", ecom_str);
			XFREE(MTYPE_ECOMMUNITY_STR, ecom_str);
		}
	}

	/* export route-target */
	if (CHECK_FLAG(bgp->vrf_flags, BGP_VRF_EXPORT_RT_CFGD)) {
		char *ecom_str;
		struct listnode *node, *nnode;
		struct ecommunity *ecom;

		for (ALL_LIST_ELEMENTS(bgp->vrf_export_rtl, node, nnode,
				       ecom)) {
			ecom_str = ecommunity_ecom2str(
				ecom, ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
			vty_out(vty, "  route-target export %s\n", ecom_str);
			XFREE(MTYPE_ECOMMUNITY_STR, ecom_str);
		}
	}
}

void bgp_ethernetvpn_init(void)
{
	install_element(VIEW_NODE, &show_ip_bgp_l2vpn_evpn_cmd);
	install_element(VIEW_NODE, &show_ip_bgp_l2vpn_evpn_rd_cmd);
	install_element(VIEW_NODE, &show_ip_bgp_l2vpn_evpn_all_tags_cmd);
	install_element(VIEW_NODE, &show_ip_bgp_l2vpn_evpn_rd_tags_cmd);
	install_element(VIEW_NODE,
			&show_ip_bgp_l2vpn_evpn_neighbor_routes_cmd);
	install_element(VIEW_NODE,
			&show_ip_bgp_l2vpn_evpn_rd_neighbor_routes_cmd);
	install_element(
		VIEW_NODE,
		&show_ip_bgp_l2vpn_evpn_neighbor_advertised_routes_cmd);
	install_element(
		VIEW_NODE,
		&show_ip_bgp_l2vpn_evpn_rd_neighbor_advertised_routes_cmd);
	install_element(VIEW_NODE, &show_ip_bgp_evpn_rd_overlay_cmd);
	install_element(VIEW_NODE, &show_ip_bgp_l2vpn_evpn_all_overlay_cmd);
	install_element(BGP_EVPN_NODE, &no_evpnrt5_network_cmd);
	install_element(BGP_EVPN_NODE, &evpnrt5_network_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_advertise_all_vni_cmd);
	install_element(BGP_EVPN_NODE, &no_bgp_evpn_advertise_all_vni_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_advertise_autort_rfc8365_cmd);
	install_element(BGP_EVPN_NODE, &no_bgp_evpn_advertise_autort_rfc8365_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_advertise_default_gw_cmd);
	install_element(BGP_EVPN_NODE, &no_bgp_evpn_advertise_default_gw_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_advertise_svi_ip_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_advertise_type5_cmd);
	install_element(BGP_EVPN_NODE, &no_bgp_evpn_advertise_type5_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_default_originate_cmd);
	install_element(BGP_EVPN_NODE, &no_bgp_evpn_default_originate_cmd);
	install_element(BGP_EVPN_NODE, &dup_addr_detection_cmd);
	install_element(BGP_EVPN_NODE, &dup_addr_detection_auto_recovery_cmd);
	install_element(BGP_EVPN_NODE, &no_dup_addr_detection_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_flood_control_cmd);

	/* test commands */
	install_element(BGP_EVPN_NODE, &test_adv_evpn_type4_route_cmd);
	install_element(BGP_EVPN_NODE, &test_withdraw_evpn_type4_route_cmd);

	/* "show bgp l2vpn evpn" commands. */
	install_element(VIEW_NODE, &show_bgp_l2vpn_evpn_es_cmd);
	install_element(VIEW_NODE, &show_bgp_l2vpn_evpn_vni_cmd);
	install_element(VIEW_NODE, &show_bgp_l2vpn_evpn_summary_cmd);
	install_element(VIEW_NODE, &show_bgp_l2vpn_evpn_route_cmd);
	install_element(VIEW_NODE, &show_bgp_l2vpn_evpn_route_rd_cmd);
	install_element(VIEW_NODE, &show_bgp_l2vpn_evpn_route_rd_macip_cmd);
	install_element(VIEW_NODE, &show_bgp_l2vpn_evpn_route_esi_cmd);
	install_element(VIEW_NODE, &show_bgp_l2vpn_evpn_route_vni_cmd);
	install_element(VIEW_NODE,
			&show_bgp_l2vpn_evpn_route_vni_multicast_cmd);
	install_element(VIEW_NODE, &show_bgp_l2vpn_evpn_route_vni_macip_cmd);
	install_element(VIEW_NODE, &show_bgp_l2vpn_evpn_route_vni_all_cmd);
	install_element(VIEW_NODE, &show_bgp_l2vpn_evpn_import_rt_cmd);
	install_element(VIEW_NODE, &show_bgp_l2vpn_evpn_vrf_import_rt_cmd);

	/* "show bgp evpn" commands. */
	install_element(VIEW_NODE, &show_bgp_evpn_vni_cmd);
	install_element(VIEW_NODE, &show_bgp_evpn_summary_cmd);
	install_element(VIEW_NODE, &show_bgp_evpn_route_cmd);
	install_element(VIEW_NODE, &show_bgp_evpn_route_rd_cmd);
	install_element(VIEW_NODE, &show_bgp_evpn_route_rd_macip_cmd);
	install_element(VIEW_NODE, &show_bgp_evpn_route_vni_cmd);
	install_element(VIEW_NODE, &show_bgp_evpn_route_vni_multicast_cmd);
	install_element(VIEW_NODE, &show_bgp_evpn_route_vni_macip_cmd);
	install_element(VIEW_NODE, &show_bgp_evpn_route_vni_all_cmd);
	install_element(VIEW_NODE, &show_bgp_evpn_import_rt_cmd);
	install_element(VIEW_NODE, &show_bgp_vrf_l3vni_info_cmd);
	install_element(VIEW_NODE, &show_bgp_l2vpn_evpn_com_cmd);

	install_element(BGP_EVPN_NODE, &bgp_evpn_vni_cmd);
	install_element(BGP_EVPN_NODE, &no_bgp_evpn_vni_cmd);
	install_element(BGP_EVPN_VNI_NODE, &exit_vni_cmd);
	install_element(BGP_EVPN_VNI_NODE, &bgp_evpn_vni_rd_cmd);
	install_element(BGP_EVPN_VNI_NODE, &no_bgp_evpn_vni_rd_cmd);
	install_element(BGP_EVPN_VNI_NODE, &no_bgp_evpn_vni_rd_without_val_cmd);
	install_element(BGP_EVPN_VNI_NODE, &bgp_evpn_vni_rt_cmd);
	install_element(BGP_EVPN_VNI_NODE, &no_bgp_evpn_vni_rt_cmd);
	install_element(BGP_EVPN_VNI_NODE, &no_bgp_evpn_vni_rt_without_val_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_vrf_rd_cmd);
	install_element(BGP_EVPN_NODE, &no_bgp_evpn_vrf_rd_cmd);
	install_element(BGP_NODE, &no_bgp_evpn_vrf_rd_without_val_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_vrf_rt_cmd);
	install_element(BGP_EVPN_NODE, &no_bgp_evpn_vrf_rt_cmd);
	install_element(BGP_EVPN_VNI_NODE, &bgp_evpn_advertise_svi_ip_vni_cmd);
	install_element(BGP_EVPN_VNI_NODE,
			&bgp_evpn_advertise_default_gw_vni_cmd);
	install_element(BGP_EVPN_VNI_NODE,
			&no_bgp_evpn_advertise_default_gw_vni_cmd);
	install_element(BGP_EVPN_VNI_NODE, &bgp_evpn_advertise_vni_subnet_cmd);
	install_element(BGP_EVPN_VNI_NODE,
			&no_bgp_evpn_advertise_vni_subnet_cmd);
}
