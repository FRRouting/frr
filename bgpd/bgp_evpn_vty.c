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
#include "bgpd/bgp_ecommunity.h"

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
};

#if defined(HAVE_CUMULUS)
static void display_vrf_import_rt(struct vty *vty,
				  struct vrf_irt_node *irt,
				  json_object *json)
{
	u_char *pnt;
	u_char type, sub_type;
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

	pnt = (u_char *)&irt->rt.val;
	type = *pnt++;
	sub_type = *pnt++;
	if (sub_type != ECOMMUNITY_ROUTE_TARGET)
		return;

	memset(&eas, 0, sizeof(eas));
	switch (type) {
	case ECOMMUNITY_ENCODE_AS:
		eas.as = (*pnt++ << 8);
		eas.as |= (*pnt++);
		pnt = ptr_get_be32(pnt, &eas.val);

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
						vrf_id_to_name(
							tmp_bgp_vrf->vrf_id)));
		else
			vty_out(vty, "  %s\n",
				vrf_id_to_name(tmp_bgp_vrf->vrf_id));
	}

	if (json) {
		json_object_object_add(json_rt, "vrfs", json_vrfs);
		json_object_object_add(json, rt_buf, json_rt);
	}
}

static void show_vrf_import_rt_entry(struct hash_backet *backet,
				     void *args[])
{
	json_object *json = NULL;
	struct vty *vty = NULL;
	struct vrf_irt_node *irt = (struct vrf_irt_node *)backet->data;

	vty = (struct vty *)args[0];
	json = (struct json_object *)args[1];

	display_vrf_import_rt(vty, irt, json);
}

static void display_import_rt(struct vty *vty, struct irt_node *irt,
			      json_object *json)
{
	u_char *pnt;
	u_char type, sub_type;
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

	pnt = (u_char *)&irt->rt.val;
	type = *pnt++;
	sub_type = *pnt++;
	if (sub_type != ECOMMUNITY_ROUTE_TARGET)
		return;

	memset(&eas, 0, sizeof(eas));
	switch (type) {
	case ECOMMUNITY_ENCODE_AS:
		eas.as = (*pnt++ << 8);
		eas.as |= (*pnt++);
		pnt = ptr_get_be32(pnt, &eas.val);

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
				json_vnis, json_object_new_int64(tmp_vpn->vni));
		else
			vty_out(vty, "  %u\n", tmp_vpn->vni);
	}

	if (json) {
		json_object_object_add(json_rt, "vnis", json_vnis);
		json_object_object_add(json, rt_buf, json_rt);
	}
}

static void show_import_rt_entry(struct hash_backet *backet, void *args[])
{
	json_object *json = NULL;
	struct vty *vty = NULL;
	struct irt_node *irt = (struct irt_node *)backet->data;

	vty = args[0];
	json = args[1];

	display_import_rt(vty, irt, json);

	return;
}

static void bgp_evpn_show_route_rd_header(struct vty *vty,
					  struct bgp_node *rd_rn,
					  json_object *json)
{
	u_int16_t type;
	struct rd_as rd_as;
	struct rd_ip rd_ip;
	u_char *pnt;
	char rd_str[RD_ADDRSTRLEN];

	pnt = rd_rn->p.u.val;

	/* Decode RD type. */
	type = decode_rd_type(pnt);

	if (json)
		return;

	vty_out(vty, "Route Distinguisher: ");

	switch (type) {
	case RD_TYPE_AS:
		decode_rd_as(pnt + 2, &rd_as);
		snprintf(rd_str, RD_ADDRSTRLEN, "%u:%d", rd_as.as, rd_as.val);
		break;

	case RD_TYPE_IP:
		decode_rd_ip(pnt + 2, &rd_ip);
		snprintf(rd_str, RD_ADDRSTRLEN, "%s:%d", inet_ntoa(rd_ip.ip),
			 rd_ip.val);
		break;

	default:
		snprintf(rd_str, RD_ADDRSTRLEN, "Unknown RD type");
		break;
	}

	vty_out(vty, "%s\n", rd_str);
}

static void bgp_evpn_show_route_header(struct vty *vty, struct bgp *bgp,
				       json_object *json)
{
	char ri_header[] =
		"   Network          Next Hop            Metric LocPrf Weight Path\n";

	if (json)
		return;


	vty_out(vty, "BGP table version is 0, local router ID is %s\n",
		inet_ntoa(bgp->router_id));
	vty_out(vty,
		"Status codes: s suppressed, d damped, h history, "
		"* valid, > best, i - internal\n");
	vty_out(vty, "Origin codes: i - IGP, e - EGP, ? - incomplete\n");
	vty_out(vty,
		"EVPN type-2 prefix: [2]:[ESI]:[EthTag]:[MAClen]:[MAC]:[IPlen]:[IP]\n");
	vty_out(vty, "EVPN type-3 prefix: [3]:[EthTag]:[IPlen]:[OrigIP]\n");
	vty_out(vty, "EVPN type-5 prefix: [5]:[ESI]:[EthTag]:[IPlen]:[IP]\n\n");
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

static void display_vni(struct vty *vty, struct bgpevpn *vpn, json_object *json)
{
	char buf1[RD_ADDRSTRLEN];
	char *ecom_str;
	struct listnode *node, *nnode;
	struct ecommunity *ecom;
	json_object *json_import_rtl = NULL;
	json_object *json_export_rtl = NULL;

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
		json_object_string_add(json, "advertiseGatewayMacip",
				       vpn->advertise_gw_macip ? "Yes" : "No");
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
		vty_out(vty, "  Advertise-gw-macip : %s\n",
			vpn->advertise_gw_macip ? "Yes" : "No");
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

static void evpn_show_vrf_routes(struct vty *vty,
				 struct bgp *bgp_vrf)
{
	struct bgp *bgp_def = NULL;
	struct bgp_node *rn;
	struct bgp_info *ri;
	int header = 1;
	u_int32_t prefix_cnt, path_cnt;
	struct bgp_table *table;

	prefix_cnt = path_cnt = 0;
	bgp_def = bgp_get_default();
	if (!bgp_def)
		return;

	table = (struct bgp_table *)bgp_vrf->rib[AFI_L2VPN][SAFI_EVPN];
	for (rn = bgp_table_top(table); rn; rn = bgp_route_next(rn)) {
		char prefix_str[BUFSIZ];

		bgp_evpn_route2str((struct prefix_evpn *)&rn->p, prefix_str,
				   sizeof(prefix_str));

		if (rn->info) {
			/* Overall header/legend displayed once. */
			if (header) {
				bgp_evpn_show_route_header(vty, bgp_def, NULL);
				header = 0;
			}
			prefix_cnt++;
		}

		/* For EVPN, the prefix is displayed for each path (to fit in
		 * with code that already exists).
		 */
		for (ri = rn->info; ri; ri = ri->next) {
			route_vty_out(vty, &rn->p, ri, 0, SAFI_EVPN, NULL);
			path_cnt++;
		}
	}

	if (prefix_cnt == 0)
		vty_out(vty, "No EVPN prefixes exist for this VRF");
	else
		vty_out(vty, "\nDisplayed %u prefixes (%u paths)",
			prefix_cnt, path_cnt);
}

static void show_vni_routes(struct bgp *bgp, struct bgpevpn *vpn, int type,
			    struct vty *vty, struct in_addr vtep_ip,
			    json_object *json)
{
	struct bgp_node *rn;
	struct bgp_info *ri;
	int header = 1;
	u_int32_t prefix_cnt, path_cnt;

	prefix_cnt = path_cnt = 0;

	for (rn = bgp_table_top(vpn->route_table); rn;
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

		if (rn->info) {
			/* Overall header/legend displayed once. */
			if (header) {
				bgp_evpn_show_route_header(vty, bgp, json);
				header = 0;
			}

			prefix_cnt++;
		}

		if (json)
			json_paths = json_object_new_array();

		/* For EVPN, the prefix is displayed for each path (to fit in
		 * with code that already exists).
		 */
		for (ri = rn->info; ri; ri = ri->next) {
			json_object *json_path = NULL;

			if (vtep_ip.s_addr
			    && !IPV4_ADDR_SAME(&(vtep_ip),
					       &(ri->attr->nexthop)))
				continue;

			if (json)
				json_path = json_object_new_array();

			route_vty_out(vty, &rn->p, ri, 0, SAFI_EVPN, json_path);

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
			vty_out(vty, "\nDisplayed %u prefixes (%u paths)%s",
				prefix_cnt, path_cnt,
				type ? " (of requested type)" : "");
	}
}

static void show_vni_routes_hash(struct hash_backet *backet, void *arg)
{
	struct bgpevpn *vpn = (struct bgpevpn *)backet->data;
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

	show_vni_routes(wctx->bgp, vpn, 0, wctx->vty, wctx->vtep_ip, json_vni);

	if (json)
		json_object_object_add(json, vni_str, json_vni);
}

static void show_l3vni_entry(struct vty *vty, struct bgp *bgp,
			   json_object *json)
{
	json_object *json_vni;
	json_object *json_import_rtl;
	json_object *json_export_rtl;
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
		vty_out(vty, "%-1s %-10u %-4s %-21s",
			buf1, bgp->l3vni, "L3",
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

static void show_vni_entry(struct hash_backet *backet, void *args[])
{
	struct vty *vty;
	json_object *json;
	json_object *json_vni = NULL;
	json_object *json_import_rtl = NULL;
	json_object *json_export_rtl = NULL;
	struct bgpevpn *vpn = (struct bgpevpn *)backet->data;
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
		vty_out(vty, "%-1s %-10u %-4s %-21s",
			buf1, vpn->vni, "L2",
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
#endif /* HAVE_CUMULUS */

static int bgp_show_ethernet_vpn(struct vty *vty, struct prefix_rd *prd,
				 enum bgp_show_type type, void *output_arg,
				 int option, u_char use_json)
{
	afi_t afi = AFI_L2VPN;
	struct bgp *bgp;
	struct bgp_table *table;
	struct bgp_node *rn;
	struct bgp_node *rm;
	struct bgp_info *ri;
	int rd_header;
	int header = 1;

	unsigned long output_count = 0;
	unsigned long total_count = 0;
	json_object *json = NULL;
	json_object *json_nroute = NULL;
	json_object *json_array = NULL;
	json_object *json_scode = NULL;
	json_object *json_ocode = NULL;

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
		json = json_object_new_object();
		json_nroute = json_object_new_object();

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

	for (rn = bgp_table_top(bgp->rib[afi][SAFI_EVPN]); rn;
	     rn = bgp_route_next(rn)) {
		if (use_json)
			continue; /* XXX json TODO */

		if (prd && memcmp(rn->p.u.val, prd->val, 8) != 0)
			continue;

		if ((table = rn->info) == NULL)
			continue;

		rd_header = 1;

		for (rm = bgp_table_top(table); rm; rm = bgp_route_next(rm))
			for (ri = rm->info; ri; ri = ri->next) {
				total_count++;
				if (type == bgp_show_type_neighbor) {
					union sockunion *su = output_arg;

					if (ri->peer->su_remote == NULL
					    || !sockunion_same(
						       ri->peer->su_remote, su))
						continue;
				}
				if (header == 0) {
					if (use_json) {
						if (option
						    == SHOW_DISPLAY_TAGS) {
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
						}
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
					}
					header = 0;
				}
				if (rd_header) {
					u_int16_t type;
					struct rd_as rd_as;
					struct rd_ip rd_ip;
					u_char *pnt;

					pnt = rn->p.u.val;

					/* Decode RD type. */
					type = decode_rd_type(pnt);
					/* Decode RD value. */
					if (type == RD_TYPE_AS)
						decode_rd_as(pnt + 2, &rd_as);
					else if (type == RD_TYPE_AS4)
						decode_rd_as4(pnt + 2, &rd_as);
					else if (type == RD_TYPE_IP)
						decode_rd_ip(pnt + 2, &rd_ip);
					if (use_json) {
						char buffer[BUFSIZ];
						if (type == RD_TYPE_AS
						    || type == RD_TYPE_AS4)
							sprintf(buffer, "%u:%d",
								rd_as.as,
								rd_as.val);
						else if (type == RD_TYPE_IP)
							sprintf(buffer, "%s:%d",
								inet_ntoa(
									rd_ip.ip),
								rd_ip.val);
						json_object_string_add(
							json_nroute,
							"routeDistinguisher",
							buffer);
					} else {
						vty_out(vty,
							"Route Distinguisher: ");
						if (type == RD_TYPE_AS)
							vty_out(vty,
								"as2 %u:%d",
								rd_as.as,
								rd_as.val);
						else if (type == RD_TYPE_AS4)
							vty_out(vty,
								"as4 %u:%d",
								rd_as.as,
								rd_as.val);
						else if (type == RD_TYPE_IP)
							vty_out(vty, "ip %s:%d",
								inet_ntoa(
									rd_ip.ip),
								rd_ip.val);
						vty_out(vty, "\n\n");
					}
					rd_header = 0;
				}
				if (use_json)
					json_array = json_object_new_array();
				else
					json_array = NULL;
				if (option == SHOW_DISPLAY_TAGS)
					route_vty_out_tag(vty, &rm->p, ri, 0,
							  SAFI_EVPN,
							  json_array);
				else if (option == SHOW_DISPLAY_OVERLAY)
					route_vty_out_overlay(vty, &rm->p, ri,
							      0, json_array);
				else
					route_vty_out(vty, &rm->p, ri, 0,
						      SAFI_EVPN, json_array);
				output_count++;
			}
		/* XXX json */
	}
	if (output_count == 0)
		vty_out(vty, "No prefixes displayed, %ld exist\n", total_count);
	else
		vty_out(vty, "\nDisplayed %ld out of %ld total prefixes\n",
			output_count, total_count);
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

DEFUN(show_ip_bgp_l2vpn_evpn_all_neighbor_routes,
      show_ip_bgp_l2vpn_evpn_all_neighbor_routes_cmd,
      "show [ip] bgp l2vpn evpn all neighbors A.B.C.D routes [json]",
      SHOW_STR
      IP_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "Display information about all EVPN NLRIs\n"
      "Detailed information on TCP and BGP neighbor connections\n"
      "Neighbor to display information about\n"
      "Display routes learned from neighbor\n" JSON_STR)
{
	int idx_ipv4 = 0;
	union sockunion su;
	struct peer *peer;
	int ret;
	u_char uj = use_json(argc, argv);

	argv_find(argv, argc, "A.B.C.D", &idx_ipv4);

	ret = str2sockunion(argv[idx_ipv4]->arg, &su);
	if (ret < 0) {
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
				argv[idx_ipv4]->arg);
		return CMD_WARNING;
	}

	peer = peer_lookup(NULL, &su);
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

	return bgp_show_ethernet_vpn(vty, NULL, bgp_show_type_neighbor, &su, 0,
				     uj);
}

DEFUN(show_ip_bgp_l2vpn_evpn_rd_neighbor_routes,
      show_ip_bgp_l2vpn_evpn_rd_neighbor_routes_cmd,
      "show [ip] bgp l2vpn evpn rd ASN:NN_OR_IP-ADDRESS:NN neighbors A.B.C.D routes [json]",
      SHOW_STR
      IP_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "Display information for a route distinguisher\n"
      "VPN Route Distinguisher\n"
      "Detailed information on TCP and BGP neighbor connections\n"
      "Neighbor to display information about\n"
      "Display routes learned from neighbor\n" JSON_STR)
{
	int idx_ext_community = 0;
	int idx_ipv4 = 0;
	int ret;
	union sockunion su;
	struct peer *peer;
	struct prefix_rd prd;
	u_char uj = use_json(argc, argv);

	argv_find(argv, argc, "ASN:NN_OR_IP-ADDRESS:NN", &idx_ext_community);
	argv_find(argv, argc, "A.B.C.D", &idx_ipv4);

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

	ret = str2sockunion(argv[idx_ipv4]->arg, &su);
	if (ret < 0) {
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
				argv[idx_ext_community]->arg);
		return CMD_WARNING;
	}

	peer = peer_lookup(NULL, &su);
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

	return bgp_show_ethernet_vpn(vty, &prd, bgp_show_type_neighbor, &su, 0,
				     uj);
}

DEFUN(show_ip_bgp_l2vpn_evpn_all_neighbor_advertised_routes,
      show_ip_bgp_l2vpn_evpn_all_neighbor_advertised_routes_cmd,
      "show [ip] bgp l2vpn evpn all neighbors A.B.C.D advertised-routes [json]",
      SHOW_STR
      IP_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "Display information about all EVPN NLRIs\n"
      "Detailed information on TCP and BGP neighbor connections\n"
      "Neighbor to display information about\n"
      "Display the routes advertised to a BGP neighbor\n" JSON_STR)
{
	int idx_ipv4 = 0;
	int ret;
	struct peer *peer;
	union sockunion su;
	u_char uj = use_json(argc, argv);

	argv_find(argv, argc, "A.B.C.D", &idx_ipv4);

	ret = str2sockunion(argv[idx_ipv4]->arg, &su);
	if (ret < 0) {
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
				argv[idx_ipv4]->arg);
		return CMD_WARNING;
	}
	peer = peer_lookup(NULL, &su);
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
      "show [ip] bgp l2vpn evpn rd ASN:NN_OR_IP-ADDRESS:NN neighbors A.B.C.D advertised-routes [json]",
      SHOW_STR
      IP_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "Display information for a route distinguisher\n"
      "VPN Route Distinguisher\n"
      "Detailed information on TCP and BGP neighbor connections\n"
      "Neighbor to display information about\n"
      "Display the routes advertised to a BGP neighbor\n" JSON_STR)
{
	int idx_ext_community = 0;
	int idx_ipv4 = 0;
	int ret;
	struct peer *peer;
	struct prefix_rd prd;
	union sockunion su;
	u_char uj = use_json(argc, argv);

	argv_find(argv, argc, "ASN:NN_OR_IP-ADDRESS:NN", &idx_ext_community);
	argv_find(argv, argc, "A.B.C.D", &idx_ipv4);

	ret = str2sockunion(argv[idx_ipv4]->arg, &su);
	if (ret < 0) {
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
				argv[idx_ext_community]->arg);
		return CMD_WARNING;
	}
	peer = peer_lookup(NULL, &su);
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
      "show [ip] bgp l2vpn evpn all overlay",
      SHOW_STR
      IP_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "Display information about all EVPN NLRIs\n"
      "Display BGP Overlay Information for prefixes\n")
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

/* For testing purpose, static route of MPLS-VPN. */
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
		argv[idx_route_distinguisher]->arg, argv[idx_label]->arg,
		NULL,
		BGP_EVPN_IP_PREFIX_ROUTE, argv[idx_esi]->arg,
		argv[idx_gwip]->arg, argv[idx_ethtag]->arg,
		argv[idx_routermac]->arg);
}

/* For testing purpose, static route of MPLS-VPN. */
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

#if defined(HAVE_CUMULUS)

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
		for (ALL_LIST_ELEMENTS(vpn->import_rtl, node, nnode, ecom))
			ecommunity_free(&ecom);

		list_delete_all_node(vpn->import_rtl);
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
		for (ALL_LIST_ELEMENTS(vpn->export_rtl, node, nnode, ecom))
			ecommunity_free(&ecom);

		list_delete_all_node(vpn->export_rtl);
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
static void evpn_configure_vrf_rd(struct bgp *bgp_vrf,
				  struct prefix_rd *rd)
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

	if (!bgp->vnihash)
		return NULL;

	vpn = bgp_evpn_lookup_vni(bgp, vni);
	if (!vpn) {
		/* tenant vrf will be updated when we get local_vni_add from
		 * zebra
		 */
		vpn = bgp_evpn_new(bgp, vni, bgp->router_id, 0);
		if (!vpn) {
			zlog_err(
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
 * bgp_def: default bgp instance
 */
static void evpn_show_vrf_import_rts(struct vty *vty,
				     struct bgp *bgp_def,
				     json_object *json)
{
	void *args[2];

	args[0] = vty;
	args[1] = json;

	hash_iterate(bgp_def->vrf_import_rt_hash,
		     (void (*)(struct hash_backet *, void *))
		     show_vrf_import_rt_entry,
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
		(void (*)(struct hash_backet *, void *))show_import_rt_entry,
		args);
}

/*
 * Display EVPN routes for all VNIs - vty handler.
 */
static void evpn_show_routes_vni_all(struct vty *vty, struct bgp *bgp,
				     struct in_addr vtep_ip, json_object *json)
{
	u_int32_t num_vnis;
	struct vni_walk_ctx wctx;

	num_vnis = hashcount(bgp->vnihash);
	if (!num_vnis)
		return;
	memset(&wctx, 0, sizeof(struct vni_walk_ctx));
	wctx.bgp = bgp;
	wctx.vty = vty;
	wctx.vtep_ip = vtep_ip;
	wctx.json = json;
	hash_iterate(bgp->vnihash, (void (*)(struct hash_backet *,
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
	struct bgp_info *ri;
	u_int32_t path_cnt = 0;
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
	if (!rn || !rn->info) {
		if (!json)
			vty_out(vty, "%% Network not in table\n");
		return;
	}

	if (json)
		json_paths = json_object_new_array();

	/* Prefix and num paths displayed once per prefix. */
	route_vty_out_detail_header(vty, bgp, rn, NULL, afi, safi, json);

	/* Display each path for this prefix. */
	for (ri = rn->info; ri; ri = ri->next) {
		json_object *json_path = NULL;

		if (json)
			json_path = json_object_new_array();

		route_vty_out_detail(vty, bgp, &rn->p, ri, afi, safi,
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
	struct bgp_info *ri;
	u_int32_t path_cnt = 0;
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
	if (!rn || !rn->info) {
		if (!json)
			vty_out(vty, "%% Network not in table\n");
		return;
	}

	if (json)
		json_paths = json_object_new_array();

	/* Prefix and num paths displayed once per prefix. */
	route_vty_out_detail_header(vty, bgp, rn, NULL, afi, safi, json);

	/* Display each path for this prefix. */
	for (ri = rn->info; ri; ri = ri->next) {
		json_object *json_path = NULL;

		if (json)
			json_path = json_object_new_array();

		route_vty_out_detail(vty, bgp, &rn->p, ri, afi, safi,
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
	show_vni_routes(bgp, vpn, type, vty, vtep_ip, json);
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
	struct bgp_info *ri;
	afi_t afi;
	safi_t safi;
	u_int32_t path_cnt = 0;
	json_object *json_paths = NULL;
	char prefix_str[BUFSIZ];

	afi = AFI_L2VPN;
	safi = SAFI_EVPN;

	/* See if route exists. Look for both non-sticky and sticky. */
	build_evpn_type2_prefix(&p, mac, ip);
	rn = bgp_afi_node_lookup(bgp->rib[afi][safi], afi, safi,
				 (struct prefix *)&p, prd);
	if (!rn || !rn->info) {
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
	for (ri = rn->info; ri; ri = ri->next) {
		json_object *json_path = NULL;

		if (json)
			json_path = json_object_new_array();

		route_vty_out_detail(vty, bgp, &rn->p, ri, afi, safi,
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
	struct bgp_info *ri;
	int rd_header = 1;
	afi_t afi;
	safi_t safi;
	u_int32_t prefix_cnt, path_cnt;
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

	table = (struct bgp_table *)rd_rn->info;
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

		if (rn->info) {
			/* RD header and legend - once overall. */
			if (rd_header && !json) {
				vty_out(vty,
					"EVPN type-2 prefix: [2]:[ESI]:[EthTag]:[MAClen]:[MAC]\n");
				vty_out(vty,
					"EVPN type-3 prefix: [3]:[EthTag]:[IPlen]:[OrigIP]\n");
				vty_out(vty,
					"EVPN type-5 prefix: [5]:[ESI]:[EthTag]:[IPlen]:[IP]\n\n");
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
		for (ri = rn->info; ri; ri = ri->next) {
			json_object *json_path = NULL;

			if (json)
				json_path = json_object_new_array();

			route_vty_out_detail(vty, bgp, &rn->p, ri, afi, safi,
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
				 json_object *json)
{
	struct bgp_node *rd_rn;
	struct bgp_table *table;
	struct bgp_node *rn;
	struct bgp_info *ri;
	int header = 1;
	int rd_header;
	afi_t afi;
	safi_t safi;
	u_int32_t prefix_cnt, path_cnt;

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

		table = (struct bgp_table *)rd_rn->info;
		if (table == NULL)
			continue;

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

			if (rn->info) {
				/* Overall header/legend displayed once. */
				if (header) {
					bgp_evpn_show_route_header(vty, bgp,
								   json);
					header = 0;
				}

				/* RD header - per RD. */
				if (rd_header) {
					bgp_evpn_show_route_rd_header(
						vty, rd_rn, json);
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

			/* For EVPN, the prefix is displayed for each path (to
			 * fit in
			 * with code that already exists).
			 */
			for (ri = rn->info; ri; ri = ri->next) {
				json_object *json_path = NULL;
				path_cnt++;
				add_prefix_to_json = 1;
				add_rd_to_json = 1;

				if (json)
					json_path = json_object_new_array();

				route_vty_out(vty, &rn->p, ri, 0, SAFI_EVPN,
					      json_path);

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

/*
 * Display specified VNI (vty handler)
 */
static void evpn_show_vni(struct vty *vty, struct bgp *bgp, vni_t vni,
			  json_object *json)
{
	u_char found = 0;
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
			"Type", "RD", "Import RT",
			"Export RT", "Tenant VRF");
	}

	/* print all L2 VNIS */
	args[0] = vty;
	args[1] = json;
	hash_iterate(bgp->vnihash,
		     (void (*)(struct hash_backet *, void *))show_vni_entry,
		     args);

	/* print all L3 VNIs */
	for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp_temp))
		show_l3vni_entry(vty, bgp_temp, json);

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
static void evpn_unset_advertise_subnet(struct bgp *bgp,
					struct bgpevpn *vpn)
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
	bgp_zebra_advertise_all_vni(bgp, bgp->advertise_all_vni);
}

/*
 * EVPN (VNI advertisement) disabled. De-register with zebra. Cleanup VNI
 * cache, EVPN routes (delete and withdraw from peers).
 */
static void evpn_unset_advertise_all_vni(struct bgp *bgp)
{
	bgp->advertise_all_vni = 0;
	bgp_zebra_advertise_all_vni(bgp, bgp->advertise_all_vni);
	bgp_evpn_cleanup_on_disable(bgp);
}
#endif /* HAVE_CUMULUS */

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

		if (vpn->advertise_subnet)
			vty_out(vty, "   advertise-subnet\n");

		vty_out(vty, "  exit-vni\n");
	}
}

static void write_vni_config_for_entry(struct hash_backet *backet,
				       struct vty *vty)
{
	struct bgpevpn *vpn = (struct bgpevpn *)backet->data;
	write_vni_config(vty, vpn);
}

#if defined(HAVE_CUMULUS)
DEFUN (bgp_evpn_advertise_default_gw_vni,
       bgp_evpn_advertise_default_gw_vni_cmd,
       "advertise-default-gw",
       "Advertise default g/w mac-ip routes in EVPN for a VNI\n")
{
	struct bgp *bgp = VTY_GET_CONTEXT(bgp);
	VTY_DECLVAR_CONTEXT_SUB(bgpevpn, vpn);

	if (!bgp)
		return CMD_WARNING;

	if (!vpn)
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

	if (!vpn)
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

	evpn_unset_advertise_default_gw(bgp, NULL);

	return CMD_SUCCESS;
}

DEFUN (bgp_evpn_advertise_all_vni,
       bgp_evpn_advertise_all_vni_cmd,
       "advertise-all-vni",
       "Advertise All local VNIs\n")
{
	struct bgp *bgp = VTY_GET_CONTEXT(bgp);

	if (!bgp)
		return CMD_WARNING;
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

DEFUN (bgp_evpn_advertise_vni_subnet,
       bgp_evpn_advertise_vni_subnet_cmd,
       "advertise-subnet",
       "Advertise the subnet corresponding to VNI\n")
{
	struct bgp *bgp_vrf = NULL;
	struct bgp *bgp = VTY_GET_CONTEXT(bgp);
	VTY_DECLVAR_CONTEXT_SUB(bgpevpn, vpn);

	if (!bgp)
		return CMD_WARNING;

	if (!vpn)
		return CMD_WARNING;

	bgp_vrf = bgp_lookup_by_vrf_id(vpn->tenant_vrf_id);
	if (!bgp_vrf)
		return CMD_WARNING;

	if (!(advertise_type5_routes(bgp_vrf, AFI_IP) ||
	      advertise_type5_routes(bgp_vrf, AFI_IP6))) {
		vty_out(vty,
			"%%Please enable ip prefix advertisement under l2vpn evpn in %s",
			vrf_id_to_name(bgp_vrf->vrf_id));
		return CMD_WARNING;
	}

	evpn_set_advertise_subnet(bgp, vpn);
	return CMD_SUCCESS;
}

DEFUN (no_bgp_evpn_advertise_vni_subnet,
       no_bgp_evpn_advertise_vni_subnet_cmd,
       "no advertise-subnet",
       NO_STR
       "Advertise All local VNIs\n")
{
	struct bgp *bgp = VTY_GET_CONTEXT(bgp);
	VTY_DECLVAR_CONTEXT_SUB(bgpevpn, vpn);

	if (!bgp)
		return CMD_WARNING;

	if (!vpn)
		return CMD_WARNING;

	evpn_unset_advertise_subnet(bgp, vpn);
	return CMD_SUCCESS;
}

DEFUN (bgp_evpn_advertise_type5,
       bgp_evpn_advertise_type5_cmd,
       "advertise " BGP_AFI_CMD_STR "" BGP_SAFI_CMD_STR,
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

	if (!(afi == AFI_IP) || (afi == AFI_IP6)) {
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
		if (!CHECK_FLAG(bgp_vrf->vrf_flags,
				BGP_VRF_ADVERTISE_IPV4_IN_EVPN)) {
			SET_FLAG(bgp_vrf->vrf_flags,
				 BGP_VRF_ADVERTISE_IPV4_IN_EVPN);
			bgp_evpn_advertise_type5_routes(bgp_vrf, afi, safi);
		}
	} else {

		/* if we are already advertising ipv6 prefix as type-5
		 * nothing to do
		 */
		if (!CHECK_FLAG(bgp_vrf->vrf_flags,
				BGP_VRF_ADVERTISE_IPV6_IN_EVPN)) {
			SET_FLAG(bgp_vrf->vrf_flags,
				 BGP_VRF_ADVERTISE_IPV6_IN_EVPN);
			bgp_evpn_advertise_type5_routes(bgp_vrf, afi, safi);
		}
	}
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

	if (!(afi == AFI_IP) || (afi == AFI_IP6)) {
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
		if (CHECK_FLAG(bgp_vrf->vrf_flags,
			       BGP_VRF_ADVERTISE_IPV4_IN_EVPN)) {
			bgp_evpn_withdraw_type5_routes(bgp_vrf, afi, safi);
			UNSET_FLAG(bgp_vrf->vrf_flags,
				   BGP_VRF_ADVERTISE_IPV4_IN_EVPN);
		}
	} else {

		/* if we are already advertising ipv6 prefix as type-5
		 * nothing to do
		 */
		if (CHECK_FLAG(bgp_vrf->vrf_flags,
			       BGP_VRF_ADVERTISE_IPV6_IN_EVPN)) {
			bgp_evpn_withdraw_type5_routes(bgp_vrf, afi, safi);
			UNSET_FLAG(bgp_vrf->vrf_flags,
				   BGP_VRF_ADVERTISE_IPV6_IN_EVPN);
		}
	}
	return CMD_SUCCESS;
}

/*
 * Display VNI information - for all or a specific VNI
 */
DEFUN(show_bgp_l2vpn_evpn_vni,
      show_bgp_l2vpn_evpn_vni_cmd,
      "show bgp l2vpn evpn vni [(1-16777215)] [json]",
      SHOW_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "Show VNI\n"
      "VNI number\n"
      JSON_STR)
{
	struct bgp *bgp_def;
	vni_t vni;
	int idx = 0;
	u_char uj = 0;
	json_object *json = NULL;
	u_int32_t num_l2vnis = 0;
	u_int32_t num_l3vnis = 0;
	uint32_t num_vnis = 0;
	struct listnode *node = NULL;
	struct bgp *bgp_temp = NULL;

	uj = use_json(argc, argv);

	bgp_def = bgp_get_default();
	if (!bgp_def)
		return CMD_WARNING;

	if (!argv_find(argv, argc, "evpn", &idx))
		return CMD_WARNING;

	if (uj)
		json = json_object_new_object();

	if ((uj && argc == ((idx + 1) + 2)) || (!uj && argc == (idx + 1) + 1)) {

		num_l2vnis = hashcount(bgp_def->vnihash);

		for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp_temp)) {
			if (bgp_temp->l3vni)
				num_l3vnis++;
		}
		num_vnis = num_l2vnis + num_l3vnis;
		if (uj) {
			json_object_string_add(json, "advertiseGatewayMacip",
					       bgp_def->advertise_gw_macip
						       ? "Enabled"
						       : "Disabled");
			json_object_string_add(json, "advertiseAllVnis",
					       is_evpn_enabled()
						       ? "Enabled"
						       : "Disabled");
			json_object_int_add(json, "numVnis", num_vnis);
			json_object_int_add(json, "numL2Vnis", num_l2vnis);
			json_object_int_add(json, "numL3Vnis", num_l3vnis);
		} else {
			vty_out(vty, "Advertise Gateway Macip: %s\n",
				bgp_def->advertise_gw_macip ? "Enabled"
							: "Disabled");
			vty_out(vty, "Advertise All VNI flag: %s\n",
				is_evpn_enabled() ? "Enabled" : "Disabled");
			vty_out(vty, "Number of L2 VNIs: %u\n", num_l2vnis);
			vty_out(vty, "Number of L3 VNIs: %u\n", num_l3vnis);
		}
		evpn_show_all_vnis(vty, bgp_def, json);
	} else {
		int vni_idx = 0;

		if (!argv_find(argv, argc, "vni", &vni_idx))
			return CMD_WARNING;

		/* Display specific VNI */
		vni = strtoul(argv[vni_idx + 1]->arg, NULL, 10);
		evpn_show_vni(vty, bgp_def, vni, json);
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
      "show bgp l2vpn evpn summary [json]",
      SHOW_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "Summary of BGP neighbor status\n"
      JSON_STR)
{
	u_char uj = use_json(argc, argv);
	return bgp_show_summary_vty(vty, NULL, AFI_L2VPN, SAFI_EVPN, uj);
}

/*
 * Display global EVPN routing table.
 */
DEFUN(show_bgp_l2vpn_evpn_route,
      show_bgp_l2vpn_evpn_route_cmd,
      "show bgp l2vpn evpn route [type <macip|multicast|prefix>] [json]",
      SHOW_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "EVPN route information\n"
      "Specify Route type\n"
      "MAC-IP (Type-2) route\n"
      "Multicast (Type-3) route\n"
      "Prefix route\n"
      JSON_STR)
{
	struct bgp *bgp;
	int type_idx = 0;
	int type = 0;
	u_char uj = 0;
	json_object *json = NULL;

	uj = use_json(argc, argv);

	bgp = bgp_get_default();
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
		else if (strncmp(argv[type_idx + 1]->arg, "pr", 2) == 0)
			type = BGP_EVPN_IP_PREFIX_ROUTE;
		else
			return CMD_WARNING;
	}

	evpn_show_all_routes(vty, bgp, type, json);

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
      "show bgp l2vpn evpn route rd ASN:NN_OR_IP-ADDRESS:NN [type <macip|multicast|prefix>] [json]",
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
      "Prefix route\n"
      JSON_STR)
{
	struct bgp *bgp;
	int ret;
	struct prefix_rd prd;
	int type = 0;
	int rd_idx = 0;
	int type_idx = 0;
	int uj = 0;
	json_object *json = NULL;

	bgp = bgp_get_default();
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
	int uj = 0;
	json_object *json = NULL;

	memset(&mac, 0, sizeof(struct ethaddr));
	memset(&ip, 0, sizeof(struct ipaddr));

	bgp = bgp_get_default();
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

/*
 * Display per-VRF EVPN routing table.
 */
DEFUN(show_bgp_l2vpn_evpn_route_vrf, show_bgp_l2vpn_evpn_route_vrf_cmd,
      "show bgp l2vpn evpn route vrf VRFNAME",
      SHOW_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "EVPN route information\n"
      "VRF\n"
      "VRF Name\n")
{
	int vrf_idx = 6;
	char *vrf_name = NULL;
	struct bgp *bgp_vrf = NULL;

	vrf_name = argv[vrf_idx]->arg;
	bgp_vrf = bgp_lookup_by_name(vrf_name);
	if (!bgp_vrf)
		return CMD_WARNING;

	evpn_show_vrf_routes(vty, bgp_vrf);

	return CMD_SUCCESS;
}

/*
 * Display per-VNI EVPN routing table.
 */
DEFUN(show_bgp_l2vpn_evpn_route_vni, show_bgp_l2vpn_evpn_route_vni_cmd,
      "show bgp l2vpn evpn route vni (1-16777215) [<type <macip|multicast> | vtep A.B.C.D>] [json]",
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
	int uj = 0;
	json_object *json = NULL;

	bgp = bgp_get_default();
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
      "show bgp l2vpn evpn route vni (1-16777215) mac WORD [ip WORD] [json]",
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
	int uj = 0;
	json_object *json = NULL;

	bgp = bgp_get_default();
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
      "show bgp l2vpn evpn route vni (1-16777215) multicast A.B.C.D [json]",
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
	int uj = 0;
	json_object *json = NULL;

	bgp = bgp_get_default();
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
      "show bgp l2vpn evpn route vni all [vtep A.B.C.D] [json]",
      SHOW_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "EVPN route information\n"
      "VXLAN Network Identifier\n"
      "All VNIs\n"
      "Remote VTEP\n"
      "Remote VTEP IP address\n"
      JSON_STR)
{
	struct bgp *bgp;
	struct in_addr vtep_ip;
	int idx = 0;
	int uj = 0;
	json_object *json = NULL;

	bgp = bgp_get_default();
	if (!bgp)
		return CMD_WARNING;

	/* check if we need json output */
	uj = use_json(argc, argv);
	if (uj)
		json = json_object_new_object();

	if (!argv_find(argv, argc, "evpn", &idx))
		return CMD_WARNING;

	vtep_ip.s_addr = 0;
	if ((!uj && (argc == (idx + 1 + 5) && argv[idx + 5]->arg))
	    || (uj && (argc == (idx + 1 + 6) && argv[idx + 5]->arg))) {
		if (!inet_aton(argv[idx + 5]->arg, &vtep_ip)) {
			vty_out(vty, "%% Malformed VTEP IP address\n");
			return CMD_WARNING;
		}
	}

	evpn_show_routes_vni_all(vty, bgp, vtep_ip, json);

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
	u_char uj = 0;
	struct bgp *bgp_def = NULL;
	json_object *json = NULL;

	bgp_def = bgp_get_default();
	if (!bgp_def)
		return CMD_WARNING;

	uj = use_json(argc, argv);
	if (uj)
		json = json_object_new_object();

	evpn_show_vrf_import_rts(vty, bgp_def, json);

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
	u_char uj = 0;
	json_object *json = NULL;

	bgp = bgp_get_default();
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

#if defined(HAVE_CUMULUS)
ALIAS_HIDDEN(show_bgp_l2vpn_evpn_vni, show_bgp_evpn_vni_cmd,
	     "show bgp evpn vni [(1-16777215)]", SHOW_STR BGP_STR EVPN_HELP_STR
	     "Show VNI\n"
	     "VNI number\n")

ALIAS_HIDDEN(show_bgp_l2vpn_evpn_summary, show_bgp_evpn_summary_cmd,
	     "show bgp evpn summary [json]", SHOW_STR BGP_STR EVPN_HELP_STR
	     "Summary of BGP neighbor status\n"
	     JSON_STR)

ALIAS_HIDDEN(show_bgp_l2vpn_evpn_route, show_bgp_evpn_route_cmd,
	     "show bgp evpn route [type <macip|multicast>]",
	     SHOW_STR BGP_STR EVPN_HELP_STR
	     "EVPN route information\n"
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
	"show bgp evpn route vni (1-16777215) [<type <macip|multicast> | vtep A.B.C.D>]",
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
	     "show bgp evpn route vni (1-16777215) mac WORD [ip WORD]",
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
	     "show bgp evpn route vni (1-16777215) multicast A.B.C.D",
	     SHOW_STR BGP_STR EVPN_HELP_STR
	     "EVPN route information\n"
	     "VXLAN Network Identifier\n"
	     "VNI number\n"
	     "Multicast (Type-3) route\n"
	     "Originating Router IP address\n")

ALIAS_HIDDEN(show_bgp_l2vpn_evpn_route_vni_all, show_bgp_evpn_route_vni_all_cmd,
	     "show bgp evpn route vni all [vtep A.B.C.D]",
	     SHOW_STR BGP_STR EVPN_HELP_STR
	     "EVPN route information\n"
	     "VXLAN Network Identifier\n"
	     "All VNIs\n"
	     "Remote VTEP\n"
	     "Remote VTEP IP address\n")

ALIAS_HIDDEN(show_bgp_l2vpn_evpn_import_rt, show_bgp_evpn_import_rt_cmd,
	     "show bgp evpn import-rt",
	     SHOW_STR BGP_STR EVPN_HELP_STR "Show import route target\n")
#endif

DEFUN_NOSH (bgp_evpn_vni,
            bgp_evpn_vni_cmd,
            "vni (1-16777215)",
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
       "no vni (1-16777215)",
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

	if (!bgp || !vpn)
		return CMD_WARNING;

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

	if (!bgp || !vpn)
		return CMD_WARNING;

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

	if (!bgp || !vpn)
		return CMD_WARNING;

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
	u_char uj = use_json(argc, argv);

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
			vty_out(vty, "BGP instance for VRF %s not found",
				name);
		else {
			json_object_string_add(json, "warning",
					       "BGP instance not found");
			vty_out(vty, "%s\n",
				json_object_to_json_string(json));
			json_object_free(json);
		}
		return CMD_WARNING;
	}

	if (!json) {
		vty_out(vty, "BGP VRF: %s\n", name);
		vty_out(vty, "  Local-Ip: %s\n",
			inet_ntoa(bgp->originator_ip));
		vty_out(vty, "  L3-VNI: %u\n", bgp->l3vni);
		vty_out(vty, "  Rmac: %s\n",
			prefix_mac2str(&bgp->rmac, buf, sizeof(buf)));
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
		json_object_string_add(json, "rmac",
				       prefix_mac2str(&bgp->rmac, buf,
						      sizeof(buf)));
		/* list of l2vnis */
		for (ALL_LIST_ELEMENTS_RO(bgp->l2vnis, node, vpn))
			json_object_array_add(json_vnis,
					      json_object_new_int(vpn->vni));
		json_object_object_add(json, "l2vnis", json_vnis);

		/* export rts */
		for (ALL_LIST_ELEMENTS_RO(bgp->vrf_export_rtl, node, ecom))
			json_object_array_add(json_export_rts,
					      json_object_new_string(
							ecommunity_str(ecom)));
		json_object_object_add(json, "export-rts", json_export_rts);

		/* import rts */
		for (ALL_LIST_ELEMENTS_RO(bgp->vrf_import_rtl, node, ecom))
			json_object_array_add(json_import_rts,
					      json_object_new_string(
							ecommunity_str(ecom)));
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
		if (!bgp_evpn_rt_matches_existing(bgp->vrf_import_rtl,
						  ecomadd))
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
		if (!bgp_evpn_rt_matches_existing(bgp->vrf_export_rtl,
						  ecomadd))
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

	if (!bgp || !vpn)
		return CMD_WARNING;

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

	if (!bgp || !vpn)
		return CMD_WARNING;

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

	if (!bgp || !vpn)
		return CMD_WARNING;

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
#endif
/*
 * Output EVPN configuration information.
 */
void bgp_config_write_evpn_info(struct vty *vty, struct bgp *bgp, afi_t afi,
				safi_t safi)
{
	if (bgp->vnihash)
		hash_iterate(bgp->vnihash,
			     (void (*)(struct hash_backet *,
				       void *))write_vni_config_for_entry,
			     vty);

	if (bgp->advertise_all_vni)
		vty_out(vty, "  advertise-all-vni\n");

	if (bgp->advertise_gw_macip)
		vty_out(vty, "  advertise-default-gw\n");

	if (CHECK_FLAG(bgp->vrf_flags, BGP_VRF_ADVERTISE_IPV4_IN_EVPN))
		vty_out(vty, "  advertise ipv4 unicast\n");

	if (CHECK_FLAG(bgp->vrf_flags, BGP_VRF_ADVERTISE_IPV6_IN_EVPN))
		vty_out(vty, "  advertise ipv6 unicast\n");
}

void bgp_ethernetvpn_init(void)
{
	install_element(VIEW_NODE, &show_ip_bgp_l2vpn_evpn_cmd);
	install_element(VIEW_NODE, &show_ip_bgp_l2vpn_evpn_rd_cmd);
	install_element(VIEW_NODE, &show_ip_bgp_l2vpn_evpn_all_tags_cmd);
	install_element(VIEW_NODE, &show_ip_bgp_l2vpn_evpn_rd_tags_cmd);
	install_element(VIEW_NODE,
			&show_ip_bgp_l2vpn_evpn_all_neighbor_routes_cmd);
	install_element(VIEW_NODE,
			&show_ip_bgp_l2vpn_evpn_rd_neighbor_routes_cmd);
	install_element(
		VIEW_NODE,
		&show_ip_bgp_l2vpn_evpn_all_neighbor_advertised_routes_cmd);
	install_element(
		VIEW_NODE,
		&show_ip_bgp_l2vpn_evpn_rd_neighbor_advertised_routes_cmd);
	install_element(VIEW_NODE, &show_ip_bgp_evpn_rd_overlay_cmd);
	install_element(VIEW_NODE, &show_ip_bgp_l2vpn_evpn_all_overlay_cmd);
	install_element(BGP_EVPN_NODE, &no_evpnrt5_network_cmd);
	install_element(BGP_EVPN_NODE, &evpnrt5_network_cmd);
#if defined(HAVE_CUMULUS)
	install_element(BGP_EVPN_NODE, &bgp_evpn_advertise_all_vni_cmd);
	install_element(BGP_EVPN_NODE, &no_bgp_evpn_advertise_all_vni_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_advertise_default_gw_cmd);
	install_element(BGP_EVPN_NODE, &no_bgp_evpn_advertise_default_gw_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_advertise_type5_cmd);
	install_element(BGP_EVPN_NODE, &no_bgp_evpn_advertise_type5_cmd);

	/* "show bgp l2vpn evpn" commands. */
	install_element(VIEW_NODE, &show_bgp_l2vpn_evpn_vni_cmd);
	install_element(VIEW_NODE, &show_bgp_l2vpn_evpn_summary_cmd);
	install_element(VIEW_NODE, &show_bgp_l2vpn_evpn_route_cmd);
	install_element(VIEW_NODE, &show_bgp_l2vpn_evpn_route_rd_cmd);
	install_element(VIEW_NODE, &show_bgp_l2vpn_evpn_route_rd_macip_cmd);
	install_element(VIEW_NODE, &show_bgp_l2vpn_evpn_route_vni_cmd);
	install_element(VIEW_NODE, &show_bgp_l2vpn_evpn_route_vrf_cmd);
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
	install_element(BGP_EVPN_VNI_NODE,
			&bgp_evpn_advertise_default_gw_vni_cmd);
	install_element(BGP_EVPN_VNI_NODE,
			&no_bgp_evpn_advertise_default_gw_vni_cmd);
	install_element(BGP_EVPN_VNI_NODE, &bgp_evpn_advertise_vni_subnet_cmd);
	install_element(BGP_EVPN_VNI_NODE,
			&no_bgp_evpn_advertise_vni_subnet_cmd);
#endif
}
