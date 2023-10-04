// SPDX-License-Identifier: GPL-2.0-or-later
/* Ethernet-VPN Packet and vty Processing File
 * Copyright (C) 2017 6WIND
 *
 * This file is part of FRRouting
 */

#include <zebra.h>
#include "command.h"
#include "prefix.h"
#include "lib/json.h"
#include "lib/printfrr.h"
#include "lib/vxlan.h"
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
#include "bgpd/bgp_evpn_mh.h"
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
	int type;
	bool mac_table;
};

int argv_find_and_parse_oly_idx(struct cmd_token **argv, int argc, int *oly_idx,
				enum overlay_index_type *oly)
{
	*oly = OVERLAY_INDEX_TYPE_NONE;
	if (argv_find(argv, argc, "gateway-ip", oly_idx))
		*oly = OVERLAY_INDEX_GATEWAY_IP;
	return 1;
}

static void display_vrf_import_rt(struct vty *vty, struct vrf_irt_node *irt,
				  json_object *json)
{
	const uint8_t *pnt;
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

		snprintf(rt_buf, sizeof(rt_buf), "%u:%u", eas.as, eas.val);

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

		snprintfrr(rt_buf, sizeof(rt_buf), "%pI4:%u", &eip.ip, eip.val);

		if (json)
			json_object_string_add(json_rt, "rt", rt_buf);
		else
			vty_out(vty, "Route-target: %s", rt_buf);

		break;

	case ECOMMUNITY_ENCODE_AS4:
		pnt = ptr_get_be32(pnt, &eas.val);
		eas.val = (*pnt++ << 8);
		eas.val |= (*pnt++);

		snprintf(rt_buf, sizeof(rt_buf), "%u:%u", eas.as, eas.val);

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
	const uint8_t *pnt;
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

		snprintf(rt_buf, sizeof(rt_buf), "%u:%u", eas.as, eas.val);

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

		snprintfrr(rt_buf, sizeof(rt_buf), "%pI4:%u", &eip.ip, eip.val);

		if (json)
			json_object_string_add(json_rt, "rt", rt_buf);
		else
			vty_out(vty, "Route-target: %s", rt_buf);

		break;

	case ECOMMUNITY_ENCODE_AS4:
		pnt = ptr_get_be32(pnt, &eas.val);
		eas.val = (*pnt++ << 8);
		eas.val |= (*pnt++);

		snprintf(rt_buf, sizeof(rt_buf), "%u:%u", eas.as, eas.val);

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
					  struct bgp_dest *rd_dest,
					  json_object *json, char *rd_str,
					  int len)
{
	uint16_t type;
	struct rd_as rd_as;
	struct rd_ip rd_ip;
	const uint8_t *pnt;
	const struct prefix *p = bgp_dest_get_prefix(rd_dest);

	pnt = p->u.val;

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
			vty_out(vty, "%s\n", rd_str);
		break;

	case RD_TYPE_AS4:
		decode_rd_as4(pnt + 2, &rd_as);
		snprintf(rd_str, len, "%u:%d", rd_as.as, rd_as.val);
		if (json)
			json_object_string_add(json, "rd", rd_str);
		else
			vty_out(vty, "%s\n", rd_str);
		break;

	case RD_TYPE_IP:
		decode_rd_ip(pnt + 2, &rd_ip);
		snprintfrr(rd_str, len, "%pI4:%d", &rd_ip.ip, rd_ip.val);
		if (json)
			json_object_string_add(json, "rd", rd_str);
		else
			vty_out(vty, "%s\n", rd_str);
		break;

	default:
		if (json) {
			snprintf(rd_str, len, "Unknown");
			json_object_string_add(json, "rd", rd_str);
		} else {
			snprintf(rd_str, len, "Unknown RD type");
			vty_out(vty, "%s\n", rd_str);
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

	vty_out(vty,
		"BGP table version is %" PRIu64 ", local router ID is %pI4\n",
		tbl_ver, &bgp->router_id);
	vty_out(vty,
		"Status codes: s suppressed, d damped, h history, * valid, > best, i - internal\n");
	vty_out(vty, "Origin codes: i - IGP, e - EGP, ? - incomplete\n");
	vty_out(vty,
		"EVPN type-1 prefix: [1]:[EthTag]:[ESI]:[IPlen]:[VTEP-IP]:[Frag-id]\n");
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
	char *ecom_str;
	struct listnode *node, *nnode;
	struct vrf_route_target *l3rt;
	struct bgp *bgp_evpn = NULL;
	json_object *json_import_rtl = NULL;
	json_object *json_export_rtl = NULL;

	bgp_evpn = bgp_get_evpn();
	json_import_rtl = json_export_rtl = 0;

	if (json) {
		json_import_rtl = json_object_new_array();
		json_export_rtl = json_object_new_array();
		json_object_int_add(json, "vni", bgp_vrf->l3vni);
		json_object_string_add(json, "type", "L3");
		json_object_string_add(json, "inKernel", "True");
		json_object_string_addf(json, "rd",
					BGP_RD_AS_FORMAT(bgp_vrf->asnotation),
					&bgp_vrf->vrf_prd);
		json_object_string_addf(json, "originatorIp", "%pI4",
					&bgp_vrf->originator_ip);
		if (bgp_evpn && bgp_evpn->evpn_info) {
			ecom_str = ecommunity_ecom2str(
				bgp_evpn->evpn_info->soo,
				ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
			json_object_string_add(json, "siteOfOrigin", ecom_str);
			ecommunity_strfree(&ecom_str);
		}
		json_object_string_add(json, "advertiseGatewayMacip", "n/a");
		json_object_string_add(json, "advertiseSviMacIp", "n/a");
		if (bgp_vrf->evpn_info) {
			json_object_string_add(json, "advertisePip",
					       bgp_vrf->evpn_info->advertise_pip
						       ? "Enabled"
						       : "Disabled");
			json_object_string_addf(json, "sysIP", "%pI4",
						&bgp_vrf->evpn_info->pip_ip);
			json_object_string_addf(json, "sysMac", "%pEA",
						&bgp_vrf->evpn_info->pip_rmac);
		}
		json_object_string_addf(json, "rmac", "%pEA", &bgp_vrf->rmac);
	} else {
		vty_out(vty, "VNI: %d", bgp_vrf->l3vni);
		vty_out(vty, " (known to the kernel)");
		vty_out(vty, "\n");

		vty_out(vty, "  Type: %s\n", "L3");
		vty_out(vty, "  Tenant VRF: %s\n",
			vrf_id_to_name(bgp_vrf->vrf_id));
		vty_out(vty, "  RD: ");
		vty_out(vty, BGP_RD_AS_FORMAT(bgp_vrf->asnotation),
			&bgp_vrf->vrf_prd);
		vty_out(vty, "\n");
		vty_out(vty, "  Originator IP: %pI4\n",
			&bgp_vrf->originator_ip);
		if (bgp_evpn && bgp_evpn->evpn_info) {
			ecom_str = ecommunity_ecom2str(
				bgp_evpn->evpn_info->soo,
				ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
			vty_out(vty, "  MAC-VRF Site-of-Origin: %s\n",
				ecom_str);
			ecommunity_strfree(&ecom_str);
		}
		vty_out(vty, "  Advertise-gw-macip : %s\n", "n/a");
		vty_out(vty, "  Advertise-svi-macip : %s\n", "n/a");
		if (bgp_vrf->evpn_info) {
			vty_out(vty, "  Advertise-pip: %s\n",
				bgp_vrf->evpn_info->advertise_pip ? "Yes"
								  : "No");
			vty_out(vty, "  System-IP: %pI4\n",
				&bgp_vrf->evpn_info->pip_ip);
			vty_out(vty, "  System-MAC: %pEA\n",
				&bgp_vrf->evpn_info->pip_rmac);
		}
		vty_out(vty, "  Router-MAC: %pEA\n", &bgp_vrf->rmac);
	}

	if (!json)
		vty_out(vty, "  Import Route Target:\n");

	for (ALL_LIST_ELEMENTS(bgp_vrf->vrf_import_rtl, node, nnode, l3rt)) {
		ecom_str = ecommunity_ecom2str(l3rt->ecom,
					       ECOMMUNITY_FORMAT_ROUTE_MAP, 0);

		if (json)
			json_object_array_add(json_import_rtl,
					      json_object_new_string(ecom_str));
		else
			vty_out(vty, "    %s\n", ecom_str);

		ecommunity_strfree(&ecom_str);
	}

	if (json)
		json_object_object_add(json, "importRts", json_import_rtl);
	else
		vty_out(vty, "  Export Route Target:\n");

	for (ALL_LIST_ELEMENTS(bgp_vrf->vrf_export_rtl, node, nnode, l3rt)) {
		ecom_str = ecommunity_ecom2str(l3rt->ecom,
					       ECOMMUNITY_FORMAT_ROUTE_MAP, 0);

		if (json)
			json_object_array_add(json_export_rtl,
					      json_object_new_string(ecom_str));
		else
			vty_out(vty, "    %s\n", ecom_str);

		ecommunity_strfree(&ecom_str);
	}

	if (json)
		json_object_object_add(json, "exportRts", json_export_rtl);
}

static void display_vni(struct vty *vty, struct bgpevpn *vpn, json_object *json)
{
	char *ecom_str;
	struct listnode *node, *nnode;
	struct ecommunity *ecom;
	json_object *json_import_rtl = NULL;
	json_object *json_export_rtl = NULL;
	struct bgp *bgp_evpn;
	enum asnotation_mode asnotation;

	bgp_evpn = bgp_get_evpn();
	asnotation = bgp_get_asnotation(bgp_evpn);

	if (json) {
		json_import_rtl = json_object_new_array();
		json_export_rtl = json_object_new_array();
		json_object_int_add(json, "vni", vpn->vni);
		json_object_string_add(json, "type", "L2");
		json_object_string_add(json, "inKernel",
				       is_vni_live(vpn) ? "True" : "False");
		json_object_string_addf(
			json, "rd", BGP_RD_AS_FORMAT(asnotation), &vpn->prd);
		json_object_string_addf(json, "originatorIp", "%pI4",
					&vpn->originator_ip);
		json_object_string_addf(json, "mcastGroup", "%pI4",
					&vpn->mcast_grp);
		if (bgp_evpn && bgp_evpn->evpn_info) {
			ecom_str = ecommunity_ecom2str(
				bgp_evpn->evpn_info->soo,
				ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
			json_object_string_add(json, "siteOfOrigin", ecom_str);
			ecommunity_strfree(&ecom_str);
		}
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
		    bgp_evpn->evpn_info &&
		    bgp_evpn->evpn_info->advertise_svi_macip)
			json_object_string_add(json, "advertiseSviMacIp",
					       "Active");
		else if (vpn->advertise_svi_macip)
			json_object_string_add(json, "advertiseSviMacIp",
					       "Enabled");
		else
			json_object_string_add(json, "advertiseSviMacIp",
					       "Disabled");
		json_object_string_add(
			json, "sviInterface",
			ifindex2ifname(vpn->svi_ifindex, vpn->tenant_vrf_id));
	} else {
		vty_out(vty, "VNI: %u", vpn->vni);
		if (is_vni_live(vpn))
			vty_out(vty, " (known to the kernel)");
		vty_out(vty, "\n");

		vty_out(vty, "  Type: %s\n", "L2");
		vty_out(vty, "  Tenant-Vrf: %s\n",
			vrf_id_to_name(vpn->tenant_vrf_id));
		vty_out(vty, "  RD: ");
		vty_out(vty, BGP_RD_AS_FORMAT(asnotation), &vpn->prd);
		vty_out(vty, "\n");
		vty_out(vty, "  Originator IP: %pI4\n", &vpn->originator_ip);
		vty_out(vty, "  Mcast group: %pI4\n", &vpn->mcast_grp);
		if (bgp_evpn && bgp_evpn->evpn_info) {
			ecom_str = ecommunity_ecom2str(
				bgp_evpn->evpn_info->soo,
				ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
			vty_out(vty, "  MAC-VRF Site-of-Origin: %s\n",
				ecom_str);
			ecommunity_strfree(&ecom_str);
		}
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
		    bgp_evpn->evpn_info &&
		    bgp_evpn->evpn_info->advertise_svi_macip)
			vty_out(vty, "  Advertise-svi-macip : %s\n",
				"Active");
		else if (vpn->advertise_svi_macip)
			vty_out(vty, "  Advertise-svi-macip : %s\n",
				"Enabled");
		else
			vty_out(vty, "  Advertise-svi-macip : %s\n",
				"Disabled");
		vty_out(vty, "  SVI interface : %s\n",
			ifindex2ifname(vpn->svi_ifindex, vpn->tenant_vrf_id));
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

		ecommunity_strfree(&ecom_str);
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

		ecommunity_strfree(&ecom_str);
	}

	if (json)
		json_object_object_add(json, "exportRts", json_export_rtl);
}

static void show_esi_routes(struct bgp *bgp,
			    struct bgp_evpn_es *es,
			    struct vty *vty,
			    json_object *json)
{
	int header = 1;
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	uint32_t prefix_cnt, path_cnt;
	uint64_t tbl_ver;

	prefix_cnt = path_cnt = 0;

	tbl_ver = es->route_table->version;
	for (dest = bgp_table_top(es->route_table); dest;
	     dest = bgp_route_next(dest)) {
		int add_prefix_to_json = 0;
		json_object *json_paths = NULL;
		json_object *json_prefix = NULL;
		const struct prefix *p = bgp_dest_get_prefix(dest);

		if (json)
			json_prefix = json_object_new_object();

		pi = bgp_dest_get_bgp_path_info(dest);
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

			route_vty_out(vty, p, pi, 0, SAFI_EVPN, json_path,
				      false);

			if (json)
				json_object_array_add(json_paths, json_path);

			path_cnt++;
			add_prefix_to_json = 1;
		}

		if (json) {
			if (add_prefix_to_json) {
				json_object_string_addf(json_prefix, "prefix",
							"%pFX", p);
				json_object_int_add(json_prefix, "prefixLen",
						    p->prefixlen);
				json_object_object_add(json_prefix, "paths",
						       json_paths);
				json_object_object_addf(json, json_prefix,
							"%pFX", p);
			} else {
				json_object_free(json_paths);
				json_object_free(json_prefix);
				json_paths = NULL;
				json_prefix = NULL;
			}
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

/* Display all MAC-IP VNI routes linked to an ES */
static void bgp_evpn_show_routes_mac_ip_es(struct vty *vty, esi_t *esi,
					   json_object *json, int detail,
					   bool global_table)
{
	struct bgp_dest *bd;
	struct bgp_path_info *pi;
	int header = detail ? 0 : 1;
	uint32_t path_cnt;
	struct listnode *node;
	struct bgp_evpn_es *es;
	struct bgp_path_es_info *es_info;
	struct bgp *bgp = bgp_get_evpn();
	json_object *json_paths = NULL;

	if (!bgp)
		return;

	path_cnt = 0;

	if (json)
		json_paths = json_object_new_array();

	RB_FOREACH (es, bgp_es_rb_head, &bgp_mh_info->es_rb_tree) {
		struct list *es_list;

		if (esi && memcmp(esi, &es->esi, sizeof(*esi)))
			continue;

		if (global_table)
			es_list = es->macip_global_path_list;
		else
			es_list = es->macip_evi_path_list;

		for (ALL_LIST_ELEMENTS_RO(es_list, node, es_info)) {
			json_object *json_path = NULL;

			pi = es_info->pi;
			bd = pi->net;

			if (!CHECK_FLAG(pi->flags, BGP_PATH_VALID))
				continue;

			/* Overall header/legend displayed once. */
			if (header) {
				bgp_evpn_show_route_header(vty, bgp, 0, json);
				header = 0;
			}

			path_cnt++;

			if (json)
				json_path = json_object_new_array();

			if (detail)
				route_vty_out_detail(
					vty, bgp, bd, bgp_dest_get_prefix(bd),
					pi, AFI_L2VPN, SAFI_EVPN,
					RPKI_NOT_BEING_USED, json_path);
			else
				route_vty_out(vty, &bd->rn->p, pi, 0, SAFI_EVPN,
					      json_path, false);

			if (json)
				json_object_array_add(json_paths, json_path);
		}
	}

	if (json) {
		json_object_object_add(json, "paths", json_paths);
		json_object_int_add(json, "numPaths", path_cnt);
	} else {
		if (path_cnt == 0)
			vty_out(vty, "There are no MAC-IP ES paths");
		else
			vty_out(vty, "\nDisplayed %u paths\n", path_cnt);
		vty_out(vty, "\n");
	}
}

static void bgp_evpn_show_routes_mac_ip_evi_es(struct vty *vty, esi_t *esi,
					       json_object *json, int detail)
{
	bgp_evpn_show_routes_mac_ip_es(vty, esi, json, detail, false);
}

static void bgp_evpn_show_routes_mac_ip_global_es(struct vty *vty, esi_t *esi,
						  json_object *json, int detail)
{
	bgp_evpn_show_routes_mac_ip_es(vty, esi, json, detail, true);
}

static void show_vni_routes(struct bgp *bgp, struct bgpevpn *vpn,
			    struct vty *vty, int type, bool mac_table,
			    struct in_addr vtep_ip, json_object *json,
			    int detail)
{
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	struct bgp_table *table;
	int header = detail ? 0 : 1;
	uint64_t tbl_ver;
	uint32_t prefix_cnt, path_cnt;

	prefix_cnt = path_cnt = 0;

	if (mac_table)
		table = vpn->mac_table;
	else
		table = vpn->ip_table;

	tbl_ver = table->version;
	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest)) {
		const struct prefix_evpn *evp =
			(const struct prefix_evpn *)bgp_dest_get_prefix(dest);
		int add_prefix_to_json = 0;
		json_object *json_paths = NULL;
		json_object *json_prefix = NULL;
		const struct prefix *p = bgp_dest_get_prefix(dest);

		if (type && evp->prefix.route_type != type)
			continue;

		if (json)
			json_prefix = json_object_new_object();

		pi = bgp_dest_get_bgp_path_info(dest);
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
			struct prefix tmp_p;
			json_object *json_path = NULL;

			if (vtep_ip.s_addr != INADDR_ANY
			    && !IPV4_ADDR_SAME(&(vtep_ip),
					       &(pi->attr->nexthop)))
				continue;

			if (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) {
				/*
				 * VNI IP/MAC table prefixes don't have MAC/IP
				 * respectively so make sure it's set from path
				 * info here.
				 */
				if (is_evpn_prefix_ipaddr_none(evp)) {
					/* VNI MAC -> Global */
					evpn_type2_prefix_global_copy(
						(struct prefix_evpn *)&tmp_p,
						evp, NULL /* mac */,
						evpn_type2_path_info_get_ip(
							pi));
				} else {
					/* VNI IP -> Global */
					evpn_type2_prefix_global_copy(
						(struct prefix_evpn *)&tmp_p,
						evp,
						evpn_type2_path_info_get_mac(
							pi),
						NULL /* ip */);
				}
			} else
				memcpy(&tmp_p, p, sizeof(tmp_p));


			if (json)
				json_path = json_object_new_array();

			if (detail)
				route_vty_out_detail(vty, bgp, dest, &tmp_p, pi,
						     AFI_L2VPN, SAFI_EVPN,
						     RPKI_NOT_BEING_USED,
						     json_path);

			else
				route_vty_out(vty, &tmp_p, pi, 0, SAFI_EVPN,
					      json_path, false);

			if (json)
				json_object_array_add(json_paths, json_path);

			path_cnt++;
			add_prefix_to_json = 1;
		}

		if (json) {
			if (add_prefix_to_json) {
				json_object_string_addf(json_prefix, "prefix",
							"%pFX", p);
				json_object_int_add(json_prefix, "prefixLen",
						    p->prefixlen);
				json_object_object_add(json_prefix, "paths",
						       json_paths);
				json_object_object_addf(json, json_prefix,
							"%pFX", p);
			} else {
				json_object_free(json_paths);
				json_object_free(json_prefix);
				json_paths = NULL;
				json_prefix = NULL;
			}
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

	snprintf(vni_str, sizeof(vni_str), "%u", vpn->vni);
	if (json) {
		json_vni = json_object_new_object();
		json_object_int_add(json_vni, "vni", vpn->vni);
	} else {
		vty_out(vty, "\nVNI: %u\n\n", vpn->vni);
	}

	show_vni_routes(wctx->bgp, vpn, wctx->vty, wctx->type, wctx->mac_table,
			wctx->vtep_ip, json_vni, wctx->detail);

	if (json)
		json_object_object_add(json, vni_str, json_vni);
}

static void show_vni_routes_all_hash(struct hash_bucket *bucket, void *arg)
{
	struct bgpevpn *vpn = (struct bgpevpn *)bucket->data;
	struct vni_walk_ctx *wctx = arg;
	struct vty *vty = wctx->vty;
	json_object *json = wctx->json;
	json_object *json_vni = NULL;
	json_object *json_vni_mac = NULL;
	char vni_str[VNI_STR_LEN];

	snprintf(vni_str, sizeof(vni_str), "%u", vpn->vni);
	if (json) {
		json_vni = json_object_new_object();
		json_object_int_add(json_vni, "vni", vpn->vni);
	} else {
		vty_out(vty, "\nVNI: %u\n\n", vpn->vni);
	}

	show_vni_routes(wctx->bgp, vpn, wctx->vty, 0, false, wctx->vtep_ip,
			json_vni, wctx->detail);

	if (json)
		json_object_object_add(json, vni_str, json_vni);

	if (json)
		json_vni_mac = json_object_new_object();
	else
		vty_out(vty, "\nVNI: %u MAC Table\n\n", vpn->vni);

	show_vni_routes(wctx->bgp, vpn, wctx->vty, 0, true, wctx->vtep_ip,
			json_vni_mac, wctx->detail);

	if (json)
		json_object_object_add(json_vni, "macTable", json_vni_mac);
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
	struct vrf_route_target *l3rt;
	struct bgp *bgp_evpn;

	if (!bgp->l3vni)
		return;

	bgp_evpn = bgp_get_evpn();

	if (json) {
		json_vni = json_object_new_object();
		json_import_rtl = json_object_new_array();
		json_export_rtl = json_object_new_array();
	}

	/* if an l3vni is present in bgp it is live */
	buf1[0] = '\0';
	snprintf(buf1, sizeof(buf1), "*");

	if (json) {
		json_object_int_add(json_vni, "vni", bgp->l3vni);
		json_object_string_add(json_vni, "type", "L3");
		json_object_string_add(json_vni, "inKernel", "True");
		json_object_string_addf(json_vni, "originatorIp", "%pI4",
					&bgp->originator_ip);
		json_object_string_addf(json_vni, "rd",
					BGP_RD_AS_FORMAT(bgp->asnotation),
					&bgp->vrf_prd);
		json_object_string_add(json_vni, "advertiseGatewayMacip",
				       "n/a");
		json_object_string_add(json_vni, "advertiseSviMacIp", "n/a");
		json_object_string_add(
			json_vni, "advertisePip",
			bgp->evpn_info->advertise_pip ? "Enabled" : "Disabled");
		json_object_string_addf(json_vni, "sysIP", "%pI4",
					&bgp->evpn_info->pip_ip);
		json_object_string_add(json_vni, "sysMAC",
				       prefix_mac2str(&bgp->evpn_info->pip_rmac,
						      buf2, sizeof(buf2)));
		json_object_string_add(
			json_vni, "rmac",
			prefix_mac2str(&bgp->rmac, buf2, sizeof(buf2)));
	} else {
		vty_out(vty, "%-1s %-10u %-4s ", buf1, bgp->l3vni, "L3");
		vty_out(vty, BGP_RD_AS_FORMAT_SPACE(bgp->asnotation),
			&bgp->vrf_prd);
	}

	for (ALL_LIST_ELEMENTS(bgp->vrf_import_rtl, node, nnode, l3rt)) {
		ecom_str = ecommunity_ecom2str(l3rt->ecom,
					       ECOMMUNITY_FORMAT_ROUTE_MAP, 0);

		if (json) {
			json_object_array_add(json_import_rtl,
					      json_object_new_string(ecom_str));
		} else {
			if (listcount(bgp->vrf_import_rtl) > 1)
				snprintf(rt_buf, sizeof(rt_buf), "%s, ...",
					 ecom_str);
			else
				snprintf(rt_buf, sizeof(rt_buf), "%s",
					 ecom_str);
			vty_out(vty, " %-25s", rt_buf);
		}

		ecommunity_strfree(&ecom_str);

		/* If there are multiple import RTs we break here and show only
		 * one */
		if (!json)
			break;
	}

	if (json)
		json_object_object_add(json_vni, "importRTs", json_import_rtl);

	for (ALL_LIST_ELEMENTS(bgp->vrf_export_rtl, node, nnode, l3rt)) {
		ecom_str = ecommunity_ecom2str(l3rt->ecom,
					       ECOMMUNITY_FORMAT_ROUTE_MAP, 0);

		if (json) {
			json_object_array_add(json_export_rtl,
					      json_object_new_string(ecom_str));
		} else {
			if (listcount(bgp->vrf_export_rtl) > 1)
				snprintf(rt_buf, sizeof(rt_buf), "%s, ...",
					 ecom_str);
			else
				snprintf(rt_buf, sizeof(rt_buf), "%s",
					 ecom_str);
			vty_out(vty, " %-25s", rt_buf);
		}

		ecommunity_strfree(&ecom_str);

		/* If there are multiple export RTs we break here and show only
		 * one */
		if (!json) {
			if (bgp_evpn && bgp_evpn->evpn_info) {
				ecom_str = ecommunity_ecom2str(
					bgp_evpn->evpn_info->soo,
					ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
				vty_out(vty, " %-25s", ecom_str);
				ecommunity_strfree(&ecom_str);
			}
			vty_out(vty, " %-37s", vrf_id_to_name(bgp->vrf_id));
			break;
		}
	}

	if (json) {
		char vni_str[VNI_STR_LEN];

		json_object_object_add(json_vni, "exportRTs", json_export_rtl);
		if (bgp_evpn && bgp_evpn->evpn_info) {
			ecom_str = ecommunity_ecom2str(
				bgp_evpn->evpn_info->soo,
				ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
			json_object_string_add(json_vni, "siteOfOrigin",
					       ecom_str);
			ecommunity_strfree(&ecom_str);
		}
		snprintf(vni_str, sizeof(vni_str), "%u", bgp->l3vni);
		json_object_object_add(json, vni_str, json_vni);
	} else
		vty_out(vty, "\n");
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
	char rt_buf[25];
	char *ecom_str;
	struct listnode *node, *nnode;
	struct ecommunity *ecom;
	struct bgp *bgp_evpn;
	enum asnotation_mode asnotation;

	vty = args[0];
	json = args[1];

	bgp_evpn = bgp_get_evpn();
	asnotation = bgp_get_asnotation(bgp_evpn);

	if (json) {
		json_vni = json_object_new_object();
		json_import_rtl = json_object_new_array();
		json_export_rtl = json_object_new_array();
	}

	buf1[0] = '\0';
	if (is_vni_live(vpn))
		snprintf(buf1, sizeof(buf1), "*");

	if (json) {
		json_object_int_add(json_vni, "vni", vpn->vni);
		json_object_string_add(json_vni, "type", "L2");
		json_object_string_add(json_vni, "inKernel",
				       is_vni_live(vpn) ? "True" : "False");
		json_object_string_addf(json_vni, "rd",
					BGP_RD_AS_FORMAT(asnotation),
					&vpn->prd);
		json_object_string_addf(json_vni, "originatorIp", "%pI4",
					&vpn->originator_ip);
		json_object_string_addf(json_vni, "mcastGroup", "%pI4",
					&vpn->mcast_grp);
		/* per vni knob is enabled -- Enabled
		 * Global knob is enabled  -- Active
		 * default  -- Disabled
		 */
		if (!vpn->advertise_gw_macip && bgp_evpn
		    && bgp_evpn->advertise_gw_macip)
			json_object_string_add(
				json_vni, "advertiseGatewayMacip", "Active");
		else if (vpn->advertise_gw_macip)
			json_object_string_add(
				json_vni, "advertiseGatewayMacip", "Enabled");
		else
			json_object_string_add(
				json_vni, "advertiseGatewayMacip", "Disabled");
		if (!vpn->advertise_svi_macip && bgp_evpn
		    && bgp_evpn->evpn_info->advertise_svi_macip)
			json_object_string_add(json_vni, "advertiseSviMacIp",
					       "Active");
		else if (vpn->advertise_svi_macip)
			json_object_string_add(json_vni, "advertiseSviMacIp",
					       "Enabled");
		else
			json_object_string_add(json_vni, "advertiseSviMacIp",
					       "Disabled");
	} else {
		vty_out(vty, "%-1s %-10u %-4s ", buf1, vpn->vni, "L2");
		vty_out(vty, BGP_RD_AS_FORMAT_SPACE(asnotation), &vpn->prd);
	}

	for (ALL_LIST_ELEMENTS(vpn->import_rtl, node, nnode, ecom)) {
		ecom_str = ecommunity_ecom2str(ecom,
					       ECOMMUNITY_FORMAT_ROUTE_MAP, 0);

		if (json) {
			json_object_array_add(json_import_rtl,
					      json_object_new_string(ecom_str));
		} else {
			if (listcount(vpn->import_rtl) > 1)
				snprintf(rt_buf, sizeof(rt_buf), "%s, ...",
					 ecom_str);
			else
				snprintf(rt_buf, sizeof(rt_buf), "%s",
					 ecom_str);
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
				snprintf(rt_buf, sizeof(rt_buf), "%s, ...",
					 ecom_str);
			else
				snprintf(rt_buf, sizeof(rt_buf), "%s",
					 ecom_str);
			vty_out(vty, " %-25s", rt_buf);
		}

		XFREE(MTYPE_ECOMMUNITY_STR, ecom_str);

		/* If there are multiple export RTs we break here and show only
		 * one */
		if (!json) {
			if (bgp_evpn && bgp_evpn->evpn_info) {
				ecom_str = ecommunity_ecom2str(
					bgp_evpn->evpn_info->soo,
					ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
				vty_out(vty, " %-25s", ecom_str);
				ecommunity_strfree(&ecom_str);
			}
			vty_out(vty, " %-37s",
				vrf_id_to_name(vpn->tenant_vrf_id));
			break;
		}
	}

	if (json) {
		char vni_str[VNI_STR_LEN];

		json_object_object_add(json_vni, "exportRTs", json_export_rtl);
		if (bgp_evpn && bgp_evpn->evpn_info) {
			ecom_str = ecommunity_ecom2str(
				bgp_evpn->evpn_info->soo,
				ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
			json_object_string_add(json_vni, "siteOfOrigin",
					       ecom_str);
			ecommunity_strfree(&ecom_str);
		}
		snprintf(vni_str, sizeof(vni_str), "%u", vpn->vni);
		json_object_object_add(json, vni_str, json_vni);
	} else
		vty_out(vty, "\n");
}

static int bgp_show_ethernet_vpn(struct vty *vty, struct prefix_rd *prd,
				 enum bgp_show_type type, void *output_arg,
				 int option, bool use_json)
{
	afi_t afi = AFI_L2VPN;
	struct bgp *bgp;
	struct bgp_table *table;
	struct bgp_dest *dest;
	struct bgp_dest *rm;
	struct bgp_path_info *pi;
	int rd_header;
	int header = 1;
	char rd_str[RD_ADDRSTRLEN];
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

	for (dest = bgp_table_top(bgp->rib[afi][SAFI_EVPN]); dest;
	     dest = bgp_route_next(dest)) {
		uint64_t tbl_ver;
		json_object *json_nroute = NULL;
		const struct prefix *p = bgp_dest_get_prefix(dest);

		if (prd && memcmp(p->u.val, prd->val, 8) != 0)
			continue;

		table = bgp_dest_get_bgp_table_info(dest);
		if (!table)
			continue;

		rd_header = 1;
		tbl_ver = table->version;

		for (rm = bgp_table_top(table); rm; rm = bgp_route_next(rm)) {
			pi = bgp_dest_get_bgp_path_info(rm);
			if (pi == NULL)
				continue;

			no_display = 0;
			for (; pi; pi = pi->next) {
				struct community *picomm = NULL;

				picomm = bgp_attr_get_community(pi->attr);

				total_count++;
				if (type == bgp_show_type_neighbor) {
				        struct peer *peer = output_arg;

					if (peer_cmp(peer, pi->peer) != 0)
						continue;
				}
				if (type == bgp_show_type_lcommunity_exact) {
					struct lcommunity *lcom = output_arg;

					if (!bgp_attr_get_lcommunity(
						    pi->attr) ||
					    !lcommunity_cmp(
						    bgp_attr_get_lcommunity(
							    pi->attr),
						    lcom))
						continue;
				}
				if (type == bgp_show_type_lcommunity) {
					struct lcommunity *lcom = output_arg;

					if (!bgp_attr_get_lcommunity(
						    pi->attr) ||
					    !lcommunity_match(
						    bgp_attr_get_lcommunity(
							    pi->attr),
						    lcom))
						continue;
				}
				if (type == bgp_show_type_community) {
					struct community *com = output_arg;

					if (!picomm ||
					    !community_match(picomm, com))
						continue;
				}
				if (type == bgp_show_type_community_exact) {
					struct community *com = output_arg;

					if (!picomm ||
					    !community_cmp(picomm, com))
						continue;
				}
				if (header) {
					if (use_json) {
						json_object_int_add(
							json, "bgpTableVersion",
							tbl_ver);
						json_object_string_addf(
							json,
							"bgpLocalRouterId",
							"%pI4",
							&bgp->router_id);
						json_object_int_add(
							json,
							"defaultLocPrf",
							bgp->default_local_pref);
						asn_asn2json(json, "localAS",
							     bgp->as,
							     bgp->asnotation);
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
					bgp_evpn_show_route_rd_header(
						vty, dest, json_nroute, rd_str,
						RD_ADDRSTRLEN);
					rd_header = 0;
				}
				if (use_json && !json_array)
					json_array = json_object_new_array();

				if (option == SHOW_DISPLAY_TAGS)
					route_vty_out_tag(
						vty, bgp_dest_get_prefix(rm),
						pi, no_display, SAFI_EVPN,
						json_array);
				else if (option == SHOW_DISPLAY_OVERLAY)
					route_vty_out_overlay(
						vty, bgp_dest_get_prefix(rm),
						pi, no_display, json_array);
				else
					route_vty_out(vty,
						      bgp_dest_get_prefix(rm),
						      pi, no_display, SAFI_EVPN,
						      json_array, false);
				no_display = 1;
			}

			if (no_display)
				output_count++;

			if (use_json && json_array) {
				const struct prefix *p =
					bgp_dest_get_prefix(rm);

				json_prefix_info = json_object_new_object();

				json_object_string_addf(json_prefix_info,
							"prefix", "%pFX", p);

				json_object_int_add(json_prefix_info,
						    "prefixLen", p->prefixlen);

				json_object_object_add(json_prefix_info,
					"paths", json_array);
				json_object_object_addf(json_nroute,
							json_prefix_info,
							"%pFX", p);
				json_array = NULL;
			}
		}

		if (use_json && json_nroute)
			json_object_object_add(json, rd_str, json_nroute);
	}

	if (use_json) {
		json_object_int_add(json, "numPrefix", output_count);
		json_object_int_add(json, "totalPrefix", total_count);
		vty_json(vty, json);
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
	return bgp_show_ethernet_vpn(vty, NULL, bgp_show_type_normal, NULL,
				     SHOW_DISPLAY_STANDARD,
				     use_json(argc, argv));
}

DEFUN(show_ip_bgp_l2vpn_evpn_rd,
      show_ip_bgp_l2vpn_evpn_rd_cmd,
      "show [ip] bgp l2vpn evpn rd <ASN:NN_OR_IP-ADDRESS:NN|all> [json]",
      SHOW_STR
      IP_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "Display information for a route distinguisher\n"
      "VPN Route Distinguisher\n"
      "All VPN Route Distinguishers\n"
      JSON_STR)
{
	int idx_ext_community = 0;
	int ret;
	struct prefix_rd prd;
	int rd_all = 0;

	if (argv_find(argv, argc, "all", &rd_all))
		return bgp_show_ethernet_vpn(vty, NULL, bgp_show_type_normal,
					     NULL, SHOW_DISPLAY_STANDARD,
					     use_json(argc, argv));

	argv_find(argv, argc, "ASN:NN_OR_IP-ADDRESS:NN", &idx_ext_community);
	ret = str2prefix_rd(argv[idx_ext_community]->arg, &prd);
	if (!ret) {
		vty_out(vty, "%% Malformed Route Distinguisher\n");
		return CMD_WARNING;
	}
	return bgp_show_ethernet_vpn(vty, &prd, bgp_show_type_normal, NULL,
				     SHOW_DISPLAY_STANDARD,
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
	return bgp_show_ethernet_vpn(vty, NULL, bgp_show_type_normal, NULL,
				     SHOW_DISPLAY_TAGS, 0);
}

DEFUN(show_ip_bgp_l2vpn_evpn_rd_tags,
      show_ip_bgp_l2vpn_evpn_rd_tags_cmd,
      "show [ip] bgp l2vpn evpn rd <ASN:NN_OR_IP-ADDRESS:NN|all> tags",
      SHOW_STR
      IP_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "Display information for a route distinguisher\n"
      "VPN Route Distinguisher\n"
      "All VPN Route Distinguishers\n"
      "Display BGP tags for prefixes\n")
{
	int idx_ext_community = 0;
	int ret;
	struct prefix_rd prd;
	int rd_all = 0;

	if (argv_find(argv, argc, "all", &rd_all))
		return bgp_show_ethernet_vpn(vty, NULL, bgp_show_type_normal,
					     NULL, SHOW_DISPLAY_TAGS, 0);

	argv_find(argv, argc, "ASN:NN_OR_IP-ADDRESS:NN", &idx_ext_community);
	ret = str2prefix_rd(argv[idx_ext_community]->arg, &prd);
	if (!ret) {
		vty_out(vty, "%% Malformed Route Distinguisher\n");
		return CMD_WARNING;
	}
	return bgp_show_ethernet_vpn(vty, &prd, bgp_show_type_normal, NULL,
				     SHOW_DISPLAY_TAGS, 0);
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

	return bgp_show_ethernet_vpn(vty, NULL, bgp_show_type_neighbor, peer,
				     SHOW_DISPLAY_STANDARD, uj);
}

DEFUN(show_ip_bgp_l2vpn_evpn_rd_neighbor_routes,
      show_ip_bgp_l2vpn_evpn_rd_neighbor_routes_cmd,
      "show [ip] bgp l2vpn evpn rd <ASN:NN_OR_IP-ADDRESS:NN|all> neighbors <A.B.C.D|X:X::X:X|WORD> routes [json]",
      SHOW_STR
      IP_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "Display information for a route distinguisher\n"
      "VPN Route Distinguisher\n"
      "All VPN Route Distinguishers\n"
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
	struct prefix_rd prd = {};
	bool uj = use_json(argc, argv);
	afi_t afi = AFI_L2VPN;
	safi_t safi = SAFI_EVPN;
	struct bgp *bgp = NULL;
	int rd_all = 0;

	bgp_vty_find_and_parse_afi_safi_bgp(vty, argv, argc, &idx, &afi, &safi,
					    &bgp, uj);
	if (!idx) {
	        vty_out(vty, "No index\n");
		return CMD_WARNING;
	}

	if (argv_find(argv, argc, "all", &rd_all)) {
		argv_find(argv, argc, "ASN:NN_OR_IP-ADDRESS:NN",
			  &idx_ext_community);
		ret = str2prefix_rd(argv[idx_ext_community]->arg, &prd);
		if (!ret) {
			if (uj) {
				json_object *json_no = NULL;
				json_no = json_object_new_object();
				json_object_string_add(
					json_no, "warning",
					"Malformed Route Distinguisher");
				vty_out(vty, "%s\n",
					json_object_to_json_string(json_no));
				json_object_free(json_no);
			} else
				vty_out(vty,
					"%% Malformed Route Distinguisher\n");
			return CMD_WARNING;
		}
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


	if (rd_all)
		return bgp_show_ethernet_vpn(vty, NULL, bgp_show_type_neighbor,
					     peer, SHOW_DISPLAY_STANDARD, uj);
	else
		return bgp_show_ethernet_vpn(vty, &prd, bgp_show_type_neighbor,
					     peer, SHOW_DISPLAY_STANDARD, uj);
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
      "show [ip] bgp l2vpn evpn rd <ASN:NN_OR_IP-ADDRESS:NN|all> neighbors <A.B.C.D|X:X::X:X|WORD> advertised-routes [json]",
      SHOW_STR
      IP_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "Display information for a route distinguisher\n"
      "VPN Route Distinguisher\n"
      "All VPN Route Distinguishers\n"
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
	int rd_all = 0;

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

	if (argv_find(argv, argc, "all", &rd_all))
		return show_adj_route_vpn(vty, peer, NULL, AFI_L2VPN, SAFI_EVPN,
					  uj);
	else {
		argv_find(argv, argc, "ASN:NN_OR_IP-ADDRESS:NN",
			  &idx_ext_community);
		ret = str2prefix_rd(argv[idx_ext_community]->arg, &prd);
		if (!ret) {
			if (uj) {
				json_object *json_no = NULL;
				json_no = json_object_new_object();
				json_object_string_add(
					json_no, "warning",
					"Malformed Route Distinguisher");
				vty_out(vty, "%s\n",
					json_object_to_json_string(json_no));
				json_object_free(json_no);
			} else
				vty_out(vty,
					"%% Malformed Route Distinguisher\n");
			return CMD_WARNING;
		}
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
      "show [ip] bgp l2vpn evpn rd <ASN:NN_OR_IP-ADDRESS:NN|all> overlay",
      SHOW_STR
      IP_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "Display information for a route distinguisher\n"
      "VPN Route Distinguisher\n"
      "All VPN Route Distinguishers\n"
      "Display BGP Overlay Information for prefixes\n")
{
	int idx_ext_community = 0;
	int ret;
	struct prefix_rd prd;
	int rd_all = 0;

	if (argv_find(argv, argc, "all", &rd_all))
		return bgp_show_ethernet_vpn(vty, NULL, bgp_show_type_normal,
					     NULL, SHOW_DISPLAY_OVERLAY,
					     use_json(argc, argv));

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
      "network <A.B.C.D/M|X:X::X:X/M> rd ASN:NN_OR_IP-ADDRESS:NN ethtag WORD label WORD esi WORD gwip <A.B.C.D|X:X::X:X> routermac WORD [route-map RMAP_NAME]",
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

	return bgp_static_set(vty, false, argv[idx_ipv4_prefixlen]->arg,
			      argv[idx_route_distinguisher]->arg,
			      argv[idx_label]->arg, AFI_L2VPN, SAFI_EVPN, NULL,
			      0, 0, BGP_EVPN_IP_PREFIX_ROUTE,
			      argv[idx_esi]->arg, argv[idx_gwip]->arg,
			      argv[idx_ethtag]->arg, argv[idx_routermac]->arg);
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

	return bgp_static_set(vty, true, argv[idx_ipv4_prefixlen]->arg,
			      argv[idx_ext_community]->arg,
			      argv[idx_label]->arg, AFI_L2VPN, SAFI_EVPN, NULL,
			      0, 0, BGP_EVPN_IP_PREFIX_ROUTE, argv[idx_esi]->arg,
			      argv[idx_gwip]->arg, argv[idx_ethtag]->arg, NULL);
}

static void evpn_import_rt_delete_auto(struct bgp *bgp, struct bgpevpn *vpn)
{
	evpn_rt_delete_auto(bgp, vpn->vni, vpn->import_rtl, false);
}

static void evpn_export_rt_delete_auto(struct bgp *bgp, struct bgpevpn *vpn)
{
	evpn_rt_delete_auto(bgp, vpn->vni, vpn->export_rtl, false);
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
static void evpn_configure_vrf_rd(struct bgp *bgp_vrf, struct prefix_rd *rd,
				  const char *rd_pretty)
{
	/* If we have already advertise type-5 routes with a diffrent RD, we
	 * have to delete and withdraw them firs
	 */
	bgp_evpn_handle_vrf_rd_change(bgp_vrf, 1);

	if (bgp_vrf->vrf_prd_pretty)
		XFREE(MTYPE_BGP, bgp_vrf->vrf_prd_pretty);

	/* update RD */
	memcpy(&bgp_vrf->vrf_prd, rd, sizeof(struct prefix_rd));
	bgp_vrf->vrf_prd_pretty = XSTRDUP(MTYPE_BGP, rd_pretty);
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
	if (bgp_vrf->vrf_prd_pretty)
		XFREE(MTYPE_BGP, bgp_vrf->vrf_prd_pretty);
	/* We have a new RD for VRF.
	 * Advertise all type-5 routes again with the new RD
	 */
	bgp_evpn_handle_vrf_rd_change(bgp_vrf, 0);
}

/*
 * Configure RD for a VNI (vty handler)
 */
static void evpn_configure_rd(struct bgp *bgp, struct bgpevpn *vpn,
			      struct prefix_rd *rd, const char *rd_pretty)
{
	/* If the VNI is "live", we need to delete and withdraw this VNI's
	 * local routes with the prior RD first. Then, after updating RD,
	 * need to re-advertise.
	 */
	if (is_vni_live(vpn))
		bgp_evpn_handle_rd_change(bgp, vpn, 1);

	/* update RD */
	memcpy(&vpn->prd, rd, sizeof(struct prefix_rd));
	vpn->prd_pretty = XSTRDUP(MTYPE_BGP, rd_pretty);
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
		vpn = bgp_evpn_new(bgp, vni, bgp->router_id, 0, mcast_grp, 0);
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
static void evpn_delete_vni(struct bgp *bgp, struct bgpevpn *vpn)
{
	if (!is_vni_live(vpn)) {
		bgp_evpn_free(bgp, vpn);
		return;
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
static void evpn_show_routes_vni_all(struct vty *vty, struct bgp *bgp, int type,
				     bool mac_table, struct in_addr vtep_ip,
				     json_object *json, int detail)
{
	uint32_t num_vnis;
	struct vni_walk_ctx wctx;

	num_vnis = hashcount(bgp->vnihash);
	if (!num_vnis)
		return;
	memset(&wctx, 0, sizeof(wctx));
	wctx.bgp = bgp;
	wctx.vty = vty;
	wctx.type = type;
	wctx.mac_table = mac_table;
	wctx.vtep_ip = vtep_ip;
	wctx.json = json;
	wctx.detail = detail;
	hash_iterate(bgp->vnihash, (void (*)(struct hash_bucket *,
					     void *))show_vni_routes_hash,
		     &wctx);
}

/*
 * Display EVPN routes for all VNIs & all types - vty handler.
 */
static void evpn_show_routes_vni_all_type_all(struct vty *vty, struct bgp *bgp,
					      struct in_addr vtep_ip,
					      json_object *json, int detail)
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
	hash_iterate(bgp->vnihash,
		     (void (*)(struct hash_bucket *,
			       void *))show_vni_routes_all_hash,
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
	struct bgp_dest *dest;
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
	dest = bgp_evpn_vni_node_lookup(vpn, &p, NULL);
	if (!dest || !bgp_dest_has_bgp_path_info_data(dest)) {
		if (!json)
			vty_out(vty, "%% Network not in table\n");

		if (dest)
			bgp_dest_unlock_node(dest);

		return;
	}

	if (json)
		json_paths = json_object_new_array();

	/* Prefix and num paths displayed once per prefix. */
	route_vty_out_detail_header(vty, bgp, dest, bgp_dest_get_prefix(dest),
				    NULL, afi, safi, json, false);

	/* Display each path for this prefix. */
	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
		json_object *json_path = NULL;

		if (json)
			json_path = json_object_new_array();

		route_vty_out_detail(vty, bgp, dest, bgp_dest_get_prefix(dest),
				     pi, afi, safi, RPKI_NOT_BEING_USED,
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

	bgp_dest_unlock_node(dest);
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
	struct prefix_evpn tmp_p;
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	uint32_t path_cnt = 0;
	afi_t afi;
	safi_t safi;
	json_object *json_paths = NULL;
	struct ethaddr empty_mac = {};
	struct ipaddr empty_ip = {};
	const struct prefix_evpn *evp;

	afi = AFI_L2VPN;
	safi = SAFI_EVPN;

	/* Locate VNI. */
	vpn = bgp_evpn_lookup_vni(bgp, vni);
	if (!vpn) {
		if (!json)
			vty_out(vty, "VNI not found\n");
		return;
	}

	build_evpn_type2_prefix(&p, mac ? mac : &empty_mac,
				ip ? ip : &empty_ip);

	/* See if route exists. Look for both non-sticky and sticky. */
	dest = bgp_evpn_vni_node_lookup(vpn, &p, NULL);
	if (!dest || !bgp_dest_has_bgp_path_info_data(dest)) {
		if (!json)
			vty_out(vty, "%% Network not in table\n");

		if (dest)
			bgp_dest_unlock_node(dest);

		return;
	}

	/*
	 * MAC is per-path, we have to walk the path_info's and look for it
	 * first here.
	 */
	if (ip && mac) {
		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
			if (memcmp(mac, evpn_type2_path_info_get_mac(pi),
				   sizeof(*mac)) == 0)
				break;
		}

		if (!pi) {
			if (!json)
				vty_out(vty, "%% Network not in table\n");
			return;
		}
	}

	if (json)
		json_paths = json_object_new_array();

	/* Prefix and num paths displayed once per prefix. */
	route_vty_out_detail_header(vty, bgp, dest, (struct prefix *)&p, NULL,
				    afi, safi, json, false);

	evp = (const struct prefix_evpn *)bgp_dest_get_prefix(dest);

	/* Display each path for this prefix. */
	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
		json_object *json_path = NULL;

		/* skip non-matching MACs */
		if (ip && mac &&
		    memcmp(mac, evpn_type2_path_info_get_mac(pi),
			   sizeof(*mac)) != 0)
			continue;

		if (json)
			json_path = json_object_new_array();

		/*
		 * VNI table MAC-IP prefixes don't have MAC so
		 * make sure it's set from path info
		 * here.
		 */
		if (is_evpn_prefix_ipaddr_none(evp)) {
			/* VNI MAC -> Global */
			evpn_type2_prefix_global_copy(&tmp_p, evp,
						      NULL /* mac */,
						      evpn_type2_path_info_get_ip(
							      pi));
		} else {
			/* VNI IP -> Global */
			evpn_type2_prefix_global_copy(&tmp_p, evp,
						      evpn_type2_path_info_get_mac(
							      pi),
						      NULL /* ip */);
		}

		route_vty_out_detail(vty, bgp, dest, (struct prefix *)&tmp_p,
				     pi, afi, safi, RPKI_NOT_BEING_USED,
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

	bgp_dest_unlock_node(dest);
}

/* Disaplay EVPN routes for a ESI - VTY handler */
static void evpn_show_routes_esi(struct vty *vty, struct bgp *bgp,
				 esi_t *esi, json_object *json)
{
	struct bgp_evpn_es *es = NULL;

	/* locate the ES */
	es = bgp_evpn_es_find(esi);
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
				 int type, bool mac_table,
				 struct in_addr vtep_ip, json_object *json)
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
	show_vni_routes(bgp, vpn, vty, type, mac_table, vtep_ip, json, 0);
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
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	afi_t afi;
	safi_t safi;
	uint32_t path_cnt = 0;
	json_object *json_paths = NULL;

	afi = AFI_L2VPN;
	safi = SAFI_EVPN;

	/* See if route exists. Look for both non-sticky and sticky. */
	build_evpn_type2_prefix(&p, mac, ip);
	dest = bgp_safi_node_lookup(bgp->rib[afi][safi], safi,
				    (struct prefix *)&p, prd);
	if (!dest || !bgp_dest_has_bgp_path_info_data(dest)) {
		if (!json)
			vty_out(vty, "%% Network not in table\n");

		if (dest)
			bgp_dest_unlock_node(dest);

		return;
	}

	/* Prefix and num paths displayed once per prefix. */
	route_vty_out_detail_header(vty, bgp, dest, bgp_dest_get_prefix(dest),
				    prd, afi, safi, json, false);

	if (json)
		json_paths = json_object_new_array();

	/* Display each path for this prefix. */
	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
		json_object *json_path = NULL;

		if (json)
			json_path = json_object_new_array();

		route_vty_out_detail(vty, bgp, dest, bgp_dest_get_prefix(dest),
				     pi, afi, safi, RPKI_NOT_BEING_USED,
				     json_path);

		if (json)
			json_object_array_add(json_paths, json_path);

		path_cnt++;
	}

	if (json && path_cnt) {
		if (path_cnt)
			json_object_object_addf(json, json_paths, "%pFX", &p);
		json_object_int_add(json, "numPaths", path_cnt);
	} else {
		vty_out(vty, "\nDisplayed %u paths for requested prefix\n",
			path_cnt);
	}

	bgp_dest_unlock_node(dest);
}

/*
 * Display BGP EVPN routing table -- for specific RD (vty handler)
 * If 'type' is non-zero, only routes matching that type are shown.
 */
static void evpn_show_route_rd(struct vty *vty, struct bgp *bgp,
			       struct prefix_rd *prd, int type,
			       json_object *json)
{
	struct bgp_dest *rd_dest;
	struct bgp_table *table;
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	int rd_header = 1;
	afi_t afi;
	safi_t safi;
	uint32_t prefix_cnt, path_cnt;
	json_object *json_rd = NULL;
	int add_rd_to_json = 0;

	afi = AFI_L2VPN;
	safi = SAFI_EVPN;
	prefix_cnt = path_cnt = 0;

	rd_dest = bgp_node_lookup(bgp->rib[afi][safi], (struct prefix *)prd);
	if (!rd_dest)
		return;

	table = bgp_dest_get_bgp_table_info(rd_dest);
	if (table == NULL) {
		bgp_dest_unlock_node(rd_dest);
		return;
	}

	if (json) {
		json_rd = json_object_new_object();
		json_object_string_addf(json_rd, "rd",
					BGP_RD_AS_FORMAT(bgp->asnotation), prd);
	}

	bgp_dest_unlock_node(rd_dest);

	/* Display all prefixes with this RD. */
	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest)) {
		const struct prefix_evpn *evp =
			(const struct prefix_evpn *)bgp_dest_get_prefix(dest);
		json_object *json_prefix = NULL;
		json_object *json_paths = NULL;
		int add_prefix_to_json = 0;

		if (type && evp->prefix.route_type != type)
			continue;

		if (json)
			json_prefix = json_object_new_object();

		pi = bgp_dest_get_bgp_path_info(dest);
		if (pi) {
			/* RD header and legend - once overall. */
			if (rd_header && !json) {
				vty_out(vty,
					"EVPN type-1 prefix: [1]:[EthTag]:[ESI]:[IPlen]:[VTEP-IP]:[Frag-id]\n");
				vty_out(vty,
					"EVPN type-2 prefix: [2]:[EthTag]:[MAClen]:[MAC]\n");
				vty_out(vty,
					"EVPN type-3 prefix: [3]:[EthTag]:[IPlen]:[OrigIP]\n");
				vty_out(vty,
					"EVPN type-4 prefix: [4]:[ESI]:[IPlen]:[OrigIP]\n");
				vty_out(vty,
					"EVPN type-5 prefix: [5]:[EthTag]:[IPlen]:[IP]\n\n");
				rd_header = 0;
			}

			/* Prefix and num paths displayed once per prefix. */
			route_vty_out_detail_header(
				vty, bgp, dest, bgp_dest_get_prefix(dest), prd,
				afi, safi, json_prefix, false);

			prefix_cnt++;
		}

		if (json)
			json_paths = json_object_new_array();

		/* Display each path for this prefix. */
		for (; pi; pi = pi->next) {
			json_object *json_path = NULL;

			if (json)
				json_path = json_object_new_array();

			route_vty_out_detail(
				vty, bgp, dest, bgp_dest_get_prefix(dest), pi,
				afi, safi, RPKI_NOT_BEING_USED, json_path);

			if (json)
				json_object_array_add(json_paths, json_path);

			path_cnt++;
			add_prefix_to_json = 1;
			add_rd_to_json = 1;
		}

		if (json) {
			if (add_prefix_to_json) {
				json_object_object_add(json_prefix, "paths",
						       json_paths);
				json_object_object_addf(json_rd, json_prefix,
							"%pFX", evp);
			} else {
				json_object_free(json_paths);
				json_object_free(json_prefix);
				json_paths = NULL;
				json_prefix = NULL;
			}
		}
	}

	if (json) {
		if (add_rd_to_json)
			json_object_object_addf(
				json, json_rd,
				BGP_RD_AS_FORMAT(bgp->asnotation), prd);
		else {
			json_object_free(json_rd);
			json_rd = NULL;
		}

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
 * Display BGP EVPN routing table -- all RDs and MAC and/or IP
 * (vty handler).  Only matching type-2 routes will be displayed.
 */
static void evpn_show_route_rd_all_macip(struct vty *vty, struct bgp *bgp,
					 struct ethaddr *mac, struct ipaddr *ip,
					 json_object *json)
{
	struct bgp_dest *rd_dest;
	struct bgp_table *table;
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	afi_t afi = AFI_L2VPN;
	safi_t safi = SAFI_EVPN;
	uint32_t prefix_cnt, path_cnt;
	prefix_cnt = path_cnt = 0;

	/* EVPN routing table is a 2-level table with the first level being
	 * the RD. We need to look in every RD we know about.
	 */
	for (rd_dest = bgp_table_top(bgp->rib[afi][safi]); rd_dest;
	     rd_dest = bgp_route_next(rd_dest)) {
		json_object *json_paths = NULL;  /* paths array for prefix */
		json_object *json_prefix = NULL; /* prefix within an RD */
		json_object *json_rd = NULL;     /* holds all prefixes for RD */
		char rd_str[RD_ADDRSTRLEN];
		int add_rd_to_json = 0;
		struct prefix_evpn ep;
		const struct prefix *rd_destp = bgp_dest_get_prefix(rd_dest);

		table = bgp_dest_get_bgp_table_info(rd_dest);
		if (table == NULL)
			continue;

		prefix_rd2str((struct prefix_rd *)rd_destp, rd_str,
			      sizeof(rd_str), bgp->asnotation);

		/* Construct an RT-2 from the user-supplied mac(ip),
		 * then search the l2vpn evpn table for it.
		 */
		build_evpn_type2_prefix(&ep, mac, ip);
		dest = bgp_safi_node_lookup(bgp->rib[afi][safi], safi,
					    (struct prefix *)&ep,
					    (struct prefix_rd *)rd_destp);
		if (!dest)
			continue;

		if (json)
			json_rd = json_object_new_object();

		const struct prefix *p = bgp_dest_get_prefix(dest);

		pi = bgp_dest_get_bgp_path_info(dest);
		if (pi) {
			/* RD header - per RD. */
			bgp_evpn_show_route_rd_header(vty, rd_dest, json_rd,
						      rd_str, RD_ADDRSTRLEN);
			prefix_cnt++;
		}

		if (json) {
			json_prefix = json_object_new_object();
			json_paths = json_object_new_array();
			json_object_string_addf(json_prefix, "prefix", "%pFX",
						p);
			json_object_int_add(json_prefix, "prefixLen",
					    p->prefixlen);
		} else
			/* Prefix and num paths displayed once per prefix. */
			route_vty_out_detail_header(
				vty, bgp, dest, p, (struct prefix_rd *)rd_destp,
				AFI_L2VPN, SAFI_EVPN, json_prefix, false);

		/* For EVPN, the prefix is displayed for each path (to
		 * fit in with code that already exists).
		 */
		for (; pi; pi = pi->next) {
			json_object *json_path = NULL;

			add_rd_to_json = 1;
			path_cnt++;

			if (json)
				json_path = json_object_new_array();

			route_vty_out_detail(vty, bgp, dest, p, pi, AFI_L2VPN,
					     SAFI_EVPN, RPKI_NOT_BEING_USED,
					     json_path);

			if (json)
				json_object_array_add(json_paths, json_path);
			else
				vty_out(vty, "\n");
		}

		if (json) {
			json_object_object_add(json_prefix, "paths",
					       json_paths);
			json_object_object_addf(json_rd, json_prefix, "%pFX",
						p);
			if (add_rd_to_json)
				json_object_object_add(json, rd_str, json_rd);
			else {
				json_object_free(json_rd);
				json_rd = NULL;
			}
		}

		bgp_dest_unlock_node(dest);
	}

	if (json) {
		json_object_int_add(json, "numPrefix", prefix_cnt);
		json_object_int_add(json, "numPaths", path_cnt);
	} else {
		if (prefix_cnt == 0) {
			vty_out(vty, "No Matching EVPN prefixes exist\n");
		} else {
			vty_out(vty, "Displayed %u prefixes (%u paths)\n",
				prefix_cnt, path_cnt);
		}
	}
}

/*
 * Display BGP EVPN routing table - all routes (vty handler).
 * If 'type' is non-zero, only routes matching that type are shown.
 */
static void evpn_show_all_routes(struct vty *vty, struct bgp *bgp, int type,
				 json_object *json, int detail, bool self_orig)
{
	struct bgp_dest *rd_dest;
	struct bgp_table *table;
	struct bgp_dest *dest;
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
	for (rd_dest = bgp_table_top(bgp->rib[afi][safi]); rd_dest;
	     rd_dest = bgp_route_next(rd_dest)) {
		char rd_str[RD_ADDRSTRLEN];
		json_object *json_rd = NULL; /* contains routes for an RD */
		int add_rd_to_json = 0;
		uint64_t tbl_ver;
		const struct prefix *rd_destp = bgp_dest_get_prefix(rd_dest);

		table = bgp_dest_get_bgp_table_info(rd_dest);
		if (table == NULL)
			continue;

		tbl_ver = table->version;
		prefix_rd2str((struct prefix_rd *)rd_destp, rd_str,
			      sizeof(rd_str), bgp->asnotation);

		if (json)
			json_rd = json_object_new_object();

		rd_header = 1;

		/* Display all prefixes for an RD */
		for (dest = bgp_table_top(table); dest;
		     dest = bgp_route_next(dest)) {
			json_object *json_prefix =
				NULL; /* contains prefix under a RD */
			json_object *json_paths =
				NULL; /* array of paths under a prefix*/
			const struct prefix_evpn *evp =
				(const struct prefix_evpn *)bgp_dest_get_prefix(
					dest);
			int add_prefix_to_json = 0;
			const struct prefix *p = bgp_dest_get_prefix(dest);

			if (type && evp->prefix.route_type != type)
				continue;

			pi = bgp_dest_get_bgp_path_info(dest);
			if (pi) {
				if (self_orig && (pi->peer != bgp->peer_self))
					continue;

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
						vty, rd_dest, json_rd, rd_str,
						RD_ADDRSTRLEN);
					rd_header = 0;
				}

				prefix_cnt++;
			}

			if (json) {
				json_prefix = json_object_new_object();
				json_paths = json_object_new_array();
				json_object_string_addf(json_prefix, "prefix",
							"%pFX", p);
				json_object_int_add(json_prefix, "prefixLen",
						    p->prefixlen);
			}

			/* Prefix and num paths displayed once per prefix. */
			if (detail)
				route_vty_out_detail_header(
					vty, bgp, dest,
					bgp_dest_get_prefix(dest),
					(struct prefix_rd *)rd_destp, AFI_L2VPN,
					SAFI_EVPN, json_prefix, false);

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
						vty, bgp, dest,
						bgp_dest_get_prefix(dest), pi,
						AFI_L2VPN, SAFI_EVPN,
						RPKI_NOT_BEING_USED, json_path);
				} else
					route_vty_out(vty, p, pi, 0, SAFI_EVPN,
						      json_path, false);

				if (json)
					json_object_array_add(json_paths,
							      json_path);
			}

			if (json) {
				if (add_prefix_to_json) {
					json_object_object_add(json_prefix,
							       "paths",
							       json_paths);
					json_object_object_addf(json_rd,
								json_prefix,
								"%pFX", p);
				} else {
					json_object_free(json_prefix);
					json_object_free(json_paths);
					json_prefix = NULL;
					json_paths = NULL;
				}
			}
		}

		if (json) {
			if (add_rd_to_json)
				json_object_object_add(json, rd_str, json_rd);
			else {
				json_object_free(json_rd);
				json_rd = NULL;
			}
		}
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

int bgp_evpn_show_all_routes(struct vty *vty, struct bgp *bgp, int type,
			     bool use_json, int detail)
{
	json_object *json = NULL;

	if (use_json)
		json = json_object_new_object();

	evpn_show_all_routes(vty, bgp, type, json, detail, false);

	if (use_json)
		/*
		 * We are using no_pretty here because under extremely high
		 * settings (lots of routes with many different paths) this can
		 * save several minutes of output when FRR is run on older cpu's
		 * or more underperforming routers out there. So for route
		 * scale, we need to use no_pretty json.
		 */
		vty_json_no_pretty(vty, json);
	return CMD_SUCCESS;
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
		vty_out(vty, "  %-10s %-4s %-21s %-25s %-25s %-25s %-37s\n",
			"VNI", "Type", "RD", "Import RT", "Export RT",
			"MAC-VRF Site-of-Origin", "Tenant VRF");
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

/* Set resolve overlay index flag */
static void bgp_evpn_set_unset_resolve_overlay_index(struct bgp *bgp, bool set)
{
	if (set == bgp->resolve_overlay_index)
		return;

	if (set) {
		bgp->resolve_overlay_index = true;
		hash_iterate(bgp->vnihash,
			     (void (*)(struct hash_bucket *, void *))
				     bgp_evpn_handle_resolve_overlay_index_set,
			     NULL);
	} else {
		hash_iterate(
			bgp->vnihash,
			(void (*)(struct hash_bucket *, void *))
				bgp_evpn_handle_resolve_overlay_index_unset,
			NULL);
		bgp->resolve_overlay_index = false;
	}
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
	char *ecom_str;
	struct listnode *node, *nnode;
	struct ecommunity *ecom;

	if (is_vni_configured(vpn)) {
		vty_out(vty, "  vni %u\n", vpn->vni);
		if (is_rd_configured(vpn))
			vty_out(vty, "   rd %s\n", vpn->prd_pretty);

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

#include "bgpd/bgp_evpn_vty_clippy.c"

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
		vty_out(vty, "%% Please unconfigure EVPN in %s\n",
			bgp_evpn->name_pretty);
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

	if (no)
		evpn_set_advertise_svi_macip(bgp, NULL, 0);
	else {
		if (!EVPN_ENABLED(bgp)) {
			vty_out(vty,
				"This command is only supported under EVPN VRF\n");
			return CMD_WARNING;
		}
		evpn_set_advertise_svi_macip(bgp, NULL, 1);
	}

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

DEFPY(macvrf_soo_global, macvrf_soo_global_cmd,
      "mac-vrf soo ASN:NN_OR_IP-ADDRESS:NN$soo",
      "EVPN MAC-VRF\n"
      "Site-of-Origin extended community\n"
      "VPN extended community\n")
{
	struct bgp *bgp = VTY_GET_CONTEXT(bgp);
	struct bgp *bgp_evpn = bgp_get_evpn();
	struct ecommunity *ecomm_soo;

	if (!bgp || !bgp_evpn || !bgp_evpn->evpn_info)
		return CMD_WARNING;

	if (bgp != bgp_evpn) {
		vty_out(vty,
			"%% Please configure MAC-VRF SoO in the EVPN underlay: %s\n",
			bgp_evpn->name_pretty);
		return CMD_WARNING_CONFIG_FAILED;
	}

	ecomm_soo = ecommunity_str2com(soo, ECOMMUNITY_SITE_ORIGIN, 0);
	if (!ecomm_soo) {
		vty_out(vty, "%% Malformed SoO extended community\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	ecommunity_str(ecomm_soo);

	bgp_evpn_handle_global_macvrf_soo_change(bgp_evpn, ecomm_soo);

	return CMD_SUCCESS;
}

DEFPY(no_macvrf_soo_global, no_macvrf_soo_global_cmd,
      "no mac-vrf soo [ASN:NN_OR_IP-ADDRESS:NN$soo]",
      NO_STR
      "EVPN MAC-VRF\n"
      "Site-of-Origin extended community\n"
      "VPN extended community\n")
{
	struct bgp *bgp = VTY_GET_CONTEXT(bgp);
	struct bgp *bgp_evpn = bgp_get_evpn();

	if (!bgp || !bgp_evpn || !bgp_evpn->evpn_info)
		return CMD_WARNING;

	if (bgp_evpn)
		bgp_evpn_handle_global_macvrf_soo_change(bgp_evpn,
							 NULL /* new_soo */);

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
       "advertise " BGP_AFI_CMD_STR "" BGP_SAFI_CMD_STR " [gateway-ip] [route-map RMAP_NAME]",
       "Advertise prefix routes\n"
       BGP_AFI_HELP_STR
       BGP_SAFI_HELP_STR
       "advertise gateway IP overlay index\n"
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
	enum overlay_index_type oly = OVERLAY_INDEX_TYPE_NONE;
	int idx_oly = 0;
	bool adv_flag_changed = false;

	argv_find_and_parse_afi(argv, argc, &idx_afi, &afi);
	argv_find_and_parse_safi(argv, argc, &idx_safi, &safi);
	argv_find_and_parse_oly_idx(argv, argc, &idx_oly, &oly);

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
			"%% Only ipv4 or ipv6 address families are supported\n");
		return CMD_WARNING;
	}

	if (safi != SAFI_UNICAST) {
		vty_out(vty,
			"%% Only ipv4 unicast or ipv6 unicast are supported\n");
		return CMD_WARNING;
	}

	if ((oly != OVERLAY_INDEX_TYPE_NONE)
	    && (oly != OVERLAY_INDEX_GATEWAY_IP)) {
		vty_out(vty, "%% Unknown overlay-index type specified\n");
		return CMD_WARNING;
	}

	if (afi == AFI_IP) {
		if ((!CHECK_FLAG(bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
				 BGP_L2VPN_EVPN_ADV_IPV4_UNICAST))
		    && (!CHECK_FLAG(bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
				    BGP_L2VPN_EVPN_ADV_IPV4_UNICAST_GW_IP))) {

			/*
			 * this is the case for first time ever configuration
			 * adv ipv4 unicast is enabled for the first time.
			 * So no need to reset any flag
			 */
			if (oly == OVERLAY_INDEX_TYPE_NONE)
				SET_FLAG(
					bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
					BGP_L2VPN_EVPN_ADV_IPV4_UNICAST);
			else if (oly == OVERLAY_INDEX_GATEWAY_IP)
				SET_FLAG(
					bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
					BGP_L2VPN_EVPN_ADV_IPV4_UNICAST_GW_IP);
		} else if ((oly == OVERLAY_INDEX_TYPE_NONE)
			   && (!CHECK_FLAG(
				      bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
				      BGP_L2VPN_EVPN_ADV_IPV4_UNICAST))) {

			/*
			 * This is modify case from gateway-ip
			 * to no overlay index
			 */
			adv_flag_changed = true;
			UNSET_FLAG(bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
				   BGP_L2VPN_EVPN_ADV_IPV4_UNICAST_GW_IP);
			SET_FLAG(bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
				 BGP_L2VPN_EVPN_ADV_IPV4_UNICAST);
		} else if ((oly == OVERLAY_INDEX_GATEWAY_IP)
			   && (!CHECK_FLAG(
				      bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
				      BGP_L2VPN_EVPN_ADV_IPV4_UNICAST_GW_IP))) {

			/*
			 * This is modify case from no overlay index
			 * to gateway-ip
			 */
			adv_flag_changed = true;
			UNSET_FLAG(bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
				   BGP_L2VPN_EVPN_ADV_IPV4_UNICAST);
			SET_FLAG(bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
				 BGP_L2VPN_EVPN_ADV_IPV4_UNICAST_GW_IP);
		} else {

			/*
			 * Command is issued with the same option
			 * (no overlay index or gateway-ip) which was
			 * already configured. So nothing to do.
			 * However, route-map may have been modified.
			 * check if route-map has been modified.
			 * If not, return an error
			 */
			if (!rmap_changed)
				return CMD_WARNING;
		}
	} else {
		if ((!CHECK_FLAG(bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
				 BGP_L2VPN_EVPN_ADV_IPV6_UNICAST))
		    && (!CHECK_FLAG(bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
				    BGP_L2VPN_EVPN_ADV_IPV6_UNICAST_GW_IP))) {

			/*
			 * this is the case for first time ever configuration
			 * adv ipv6 unicast is enabled for the first time.
			 * So no need to reset any flag
			 */
			if (oly == OVERLAY_INDEX_TYPE_NONE)
				SET_FLAG(
					bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
					BGP_L2VPN_EVPN_ADV_IPV6_UNICAST);
			else if (oly == OVERLAY_INDEX_GATEWAY_IP)
				SET_FLAG(
					bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
					BGP_L2VPN_EVPN_ADV_IPV6_UNICAST_GW_IP);
		} else if ((oly == OVERLAY_INDEX_TYPE_NONE)
			   && (!CHECK_FLAG(
				      bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
				      BGP_L2VPN_EVPN_ADV_IPV6_UNICAST))) {

			/*
			 * This is modify case from gateway-ip
			 * to no overlay index
			 */
			adv_flag_changed = true;
			UNSET_FLAG(bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
				   BGP_L2VPN_EVPN_ADV_IPV6_UNICAST_GW_IP);
			SET_FLAG(bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
				 BGP_L2VPN_EVPN_ADV_IPV6_UNICAST);
		} else if ((oly == OVERLAY_INDEX_GATEWAY_IP)
			   && (!CHECK_FLAG(
				      bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
				      BGP_L2VPN_EVPN_ADV_IPV6_UNICAST_GW_IP))) {

			/*
			 * This is modify case from no overlay index
			 * to gateway-ip
			 */
			adv_flag_changed = true;
			UNSET_FLAG(bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
				   BGP_L2VPN_EVPN_ADV_IPV6_UNICAST);
			SET_FLAG(bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
				 BGP_L2VPN_EVPN_ADV_IPV6_UNICAST_GW_IP);
		} else {

			/*
			 * Command is issued with the same option
			 * (no overlay index or gateway-ip) which was
			 * already configured. So nothing to do.
			 * However, route-map may have been modified.
			 * check if route-map has been modified.
			 * If not, return an error
			 */
			if (!rmap_changed)
				return CMD_WARNING;
		}
	}

	if ((rmap_changed) || (adv_flag_changed)) {

		/* If either of these are changed, then FRR needs to
		 * withdraw already advertised type5 routes.
		 */
		bgp_evpn_withdraw_type5_routes(bgp_vrf, afi, safi);
		if (rmap_changed) {
			if (bgp_vrf->adv_cmd_rmap[afi][safi].name) {
				XFREE(MTYPE_ROUTE_MAP_NAME,
				      bgp_vrf->adv_cmd_rmap[afi][safi].name);
				route_map_counter_decrement(
					bgp_vrf->adv_cmd_rmap[afi][safi].map);
				bgp_vrf->adv_cmd_rmap[afi][safi].name = NULL;
				bgp_vrf->adv_cmd_rmap[afi][safi].map = NULL;
			}
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
       "no advertise " BGP_AFI_CMD_STR "" BGP_SAFI_CMD_STR " [route-map WORD]",
       NO_STR
       "Advertise prefix routes\n"
       BGP_AFI_HELP_STR
       BGP_SAFI_HELP_STR
       "route-map for filtering specific routes\n"
       "Name of the route map\n")
{
	struct bgp *bgp_vrf = VTY_GET_CONTEXT(bgp); /* bgp vrf instance */
	int idx_afi = 0;
	int idx_safi = 0;
	afi_t afi = 0;
	safi_t safi = 0;

	if (!bgp_vrf)
		return CMD_WARNING;

	argv_find_and_parse_afi(argv, argc, &idx_afi, &afi);
	argv_find_and_parse_safi(argv, argc, &idx_safi, &safi);

	if (!(afi == AFI_IP || afi == AFI_IP6)) {
		vty_out(vty,
			"%% Only ipv4 or ipv6 address families are supported\n");
		return CMD_WARNING;
	}

	if (safi != SAFI_UNICAST) {
		vty_out(vty,
			"%% Only ipv4 unicast or ipv6 unicast are supported\n");
		return CMD_WARNING;
	}

	if (afi == AFI_IP) {

		/* if we are not advertising ipv4 prefix as type-5
		 * nothing to do
		 */
		if ((CHECK_FLAG(bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
				BGP_L2VPN_EVPN_ADV_IPV4_UNICAST)) ||
		    (CHECK_FLAG(bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
				BGP_L2VPN_EVPN_ADV_IPV4_UNICAST_GW_IP))) {
			bgp_evpn_withdraw_type5_routes(bgp_vrf, afi, safi);
			UNSET_FLAG(bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
				   BGP_L2VPN_EVPN_ADV_IPV4_UNICAST);
			UNSET_FLAG(bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
				   BGP_L2VPN_EVPN_ADV_IPV4_UNICAST_GW_IP);
		}
	} else {

		/* if we are not advertising ipv6 prefix as type-5
		 * nothing to do
		 */
		if ((CHECK_FLAG(bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
				BGP_L2VPN_EVPN_ADV_IPV6_UNICAST)) ||
		    (CHECK_FLAG(bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
				BGP_L2VPN_EVPN_ADV_IPV6_UNICAST_GW_IP))){
			bgp_evpn_withdraw_type5_routes(bgp_vrf, afi, safi);
			UNSET_FLAG(bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
				   BGP_L2VPN_EVPN_ADV_IPV6_UNICAST);
			UNSET_FLAG(bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
				   BGP_L2VPN_EVPN_ADV_IPV6_UNICAST_GW_IP);
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

DEFPY (bgp_evpn_use_es_l3nhg,
       bgp_evpn_use_es_l3nhg_cmd,
       "[no$no] use-es-l3nhg",
       NO_STR
       "use L3 nexthop group for host routes with ES destination\n")
{
	bgp_mh_info->host_routes_use_l3nhg = no ? false :true;
	return CMD_SUCCESS;
}

DEFPY (bgp_evpn_ead_evi_rx_disable,
       bgp_evpn_ead_evi_rx_disable_cmd,
       "[no$no] disable-ead-evi-rx",
       NO_STR
       "Activate PE on EAD-ES even if EAD-EVI is not received\n")
{
	bool ead_evi_rx = no? true :false;

	if (ead_evi_rx != bgp_mh_info->ead_evi_rx) {
		bgp_mh_info->ead_evi_rx = ead_evi_rx;
		bgp_evpn_switch_ead_evi_rx();
	}
	return CMD_SUCCESS;
}

DEFPY (bgp_evpn_ead_evi_tx_disable,
       bgp_evpn_ead_evi_tx_disable_cmd,
       "[no$no] disable-ead-evi-tx",
       NO_STR
       "Don't advertise EAD-EVI for local ESs\n")
{
	bgp_mh_info->ead_evi_tx = no? true :false;
	return CMD_SUCCESS;
}

DEFPY (bgp_evpn_enable_resolve_overlay_index,
       bgp_evpn_enable_resolve_overlay_index_cmd,
       "[no$no] enable-resolve-overlay-index",
       NO_STR
       "Enable Recursive Resolution of type-5 route overlay index\n")
{
	struct bgp *bgp = VTY_GET_CONTEXT(bgp);

	if (bgp != bgp_get_evpn()) {
		vty_out(vty, "This command is only supported under EVPN VRF\n");
		return CMD_WARNING;
	}

	bgp_evpn_set_unset_resolve_overlay_index(bgp, no ? false : true);
	return CMD_SUCCESS;
}

DEFPY (bgp_evpn_advertise_pip_ip_mac,
       bgp_evpn_advertise_pip_ip_mac_cmd,
       "[no$no] advertise-pip [ip <A.B.C.D> [mac <X:X:X:X:X:X|X:X:X:X:X:X/M>]]",
       NO_STR
       "evpn system primary IP\n"
       IP_STR
       "ip address\n"
       MAC_STR MAC_STR MAC_STR)
{
	struct bgp *bgp_vrf = VTY_GET_CONTEXT(bgp); /* bgp vrf instance */
	struct bgp *bgp_evpn = NULL;

	if (!bgp_vrf || EVPN_ENABLED(bgp_vrf)) {
		vty_out(vty,
			"This command is supported under L3VNI BGP EVPN VRF\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	bgp_evpn = bgp_get_evpn();

	if (!no) {
		/* pip is already enabled */
		if (argc == 1 && bgp_vrf->evpn_info->advertise_pip)
			return CMD_SUCCESS;

		bgp_vrf->evpn_info->advertise_pip = true;
		if (ip.s_addr != INADDR_ANY) {
			/* Already configured with same IP */
			if (IPV4_ADDR_SAME(&ip,
					&bgp_vrf->evpn_info->pip_ip_static))
				return CMD_SUCCESS;

			bgp_vrf->evpn_info->pip_ip_static = ip;
			bgp_vrf->evpn_info->pip_ip = ip;
		} else {
			bgp_vrf->evpn_info->pip_ip_static.s_addr
				= INADDR_ANY;
			/* default instance router-id assignemt */
			if (bgp_evpn)
				bgp_vrf->evpn_info->pip_ip =
					bgp_evpn->router_id;
		}
		/* parse sys mac */
		if (!is_zero_mac(&mac->eth_addr)) {
			/* Already configured with same MAC */
			if (memcmp(&bgp_vrf->evpn_info->pip_rmac_static,
				   &mac->eth_addr, ETH_ALEN) == 0)
				return CMD_SUCCESS;

			memcpy(&bgp_vrf->evpn_info->pip_rmac_static,
			       &mac->eth_addr, ETH_ALEN);
			memcpy(&bgp_vrf->evpn_info->pip_rmac,
			       &bgp_vrf->evpn_info->pip_rmac_static,
			       ETH_ALEN);
		} else {
			/* Copy zebra sys mac */
			if (!is_zero_mac(&bgp_vrf->evpn_info->pip_rmac_zebra))
				memcpy(&bgp_vrf->evpn_info->pip_rmac,
				       &bgp_vrf->evpn_info->pip_rmac_zebra,
				       ETH_ALEN);
		}
	} else {
		if (argc == 2) {
			if (!bgp_vrf->evpn_info->advertise_pip)
				return CMD_SUCCESS;
			/* Disable PIP feature */
			bgp_vrf->evpn_info->advertise_pip = false;
			/* copy anycast mac */
			memcpy(&bgp_vrf->evpn_info->pip_rmac,
			       &bgp_vrf->rmac, ETH_ALEN);
		} else {
			/* remove MAC-IP option retain PIP knob. */
			if ((ip.s_addr != INADDR_ANY) &&
			    !IPV4_ADDR_SAME(&ip,
					&bgp_vrf->evpn_info->pip_ip_static)) {
				vty_out(vty,
					"%% BGP EVPN PIP IP does not match\n");
				return CMD_WARNING_CONFIG_FAILED;
			}

			if (!is_zero_mac(&mac->eth_addr) &&
			    memcmp(&bgp_vrf->evpn_info->pip_rmac_static,
				   &mac->eth_addr, ETH_ALEN) != 0) {
				vty_out(vty,
					"%% BGP EVPN PIP MAC does not match\n");
				return CMD_WARNING_CONFIG_FAILED;
			}
			/* pip_rmac can carry vrr_rmac reset only if it matches
			 * with static value.
			 */
			if (memcmp(&bgp_vrf->evpn_info->pip_rmac,
				   &bgp_vrf->evpn_info->pip_rmac_static,
				   ETH_ALEN) == 0) {
				/* Copy zebra sys mac */
				if (!is_zero_mac(
					&bgp_vrf->evpn_info->pip_rmac_zebra))
					memcpy(&bgp_vrf->evpn_info->pip_rmac,
					&bgp_vrf->evpn_info->pip_rmac_zebra,
					       ETH_ALEN);
				else {
					/* copy anycast mac */
					memcpy(&bgp_vrf->evpn_info->pip_rmac,
					       &bgp_vrf->rmac, ETH_ALEN);
				}
			}
		}
		/* reset user configured sys MAC */
		memset(&bgp_vrf->evpn_info->pip_rmac_static, 0, ETH_ALEN);
		/* reset user configured sys IP */
		bgp_vrf->evpn_info->pip_ip_static.s_addr = INADDR_ANY;
		/* Assign default PIP IP (bgp instance router-id) */
		if (bgp_evpn)
			bgp_vrf->evpn_info->pip_ip = bgp_evpn->router_id;
		else
			bgp_vrf->evpn_info->pip_ip.s_addr = INADDR_ANY;
	}

	if (is_evpn_enabled()) {
		struct listnode *node = NULL;
		struct bgpevpn *vpn = NULL;

		/*
		 * At this point if bgp_evpn is NULL and evpn is enabled
		 * something stupid has gone wrong
		 */
		assert(bgp_evpn);

		update_advertise_vrf_routes(bgp_vrf);

		/* Update (svi) type-2 routes */
		for (ALL_LIST_ELEMENTS_RO(bgp_vrf->l2vnis, node, vpn)) {
			if (!bgp_evpn_is_svi_macip_enabled(vpn))
				continue;
			update_routes_for_vni(bgp_evpn, vpn);
		}
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
			json_object_string_add(json, "advertiseSviMacIp",
					bgp_evpn->evpn_info->advertise_svi_macip
					? "Enabled" : "Disabled");
			json_object_string_add(json, "advertiseAllVnis",
					       is_evpn_enabled() ? "Enabled"
								 : "Disabled");
			json_object_string_add(
				json, "flooding",
				bgp_evpn->vxlan_flood_ctrl ==
						VXLAN_FLOOD_HEAD_END_REPL
					? "Head-end replication"
					: "Disabled");
			json_object_string_add(
				json, "vxlanFlooding",
				bgp_evpn->vxlan_flood_ctrl ==
						VXLAN_FLOOD_HEAD_END_REPL
					? "Enabled"
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
				bgp_evpn->vxlan_flood_ctrl ==
						VXLAN_FLOOD_HEAD_END_REPL
					? "Head-end replication"
					: "Disabled");
			vty_out(vty, "VXLAN flooding: %s\n",
				bgp_evpn->vxlan_flood_ctrl ==
						VXLAN_FLOOD_HEAD_END_REPL
					? "Enabled"
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

	if (uj)
		vty_json(vty, json);

	return CMD_SUCCESS;
}

DEFUN_HIDDEN(show_bgp_l2vpn_evpn_vni_remote_ip_hash,
	     show_bgp_l2vpn_evpn_vni_remote_ip_hash_cmd,
	     "show bgp l2vpn evpn vni remote-ip-hash",
	     SHOW_STR
	     BGP_STR
	     L2VPN_HELP_STR
	     EVPN_HELP_STR
	     "Show VNI\n"
	     "Remote IP hash\n")
{
	struct bgp *bgp_evpn;
	int idx = 0;

	bgp_evpn = bgp_get_evpn();
	if (!bgp_evpn)
		return CMD_WARNING;

	if (!argv_find(argv, argc, "evpn", &idx))
		return CMD_WARNING;

	hash_iterate(bgp_evpn->vnihash,
		     (void (*)(struct hash_bucket *,
			       void *))bgp_evpn_show_remote_ip_hash,
		     vty);

	return CMD_SUCCESS;
}

DEFUN_HIDDEN(show_bgp_l2vpn_evpn_vni_svi_hash,
	     show_bgp_l2vpn_evpn_vni_svi_hash_cmd,
	     "show bgp l2vpn evpn vni-svi-hash",
	     SHOW_STR
	     BGP_STR
	     L2VPN_HELP_STR
	     EVPN_HELP_STR
	     "Show vni-svi-hash\n")
{
	struct bgp *bgp_evpn;
	int idx = 0;

	bgp_evpn = bgp_get_evpn();
	if (!bgp_evpn)
		return CMD_WARNING;

	if (!argv_find(argv, argc, "evpn", &idx))
		return CMD_WARNING;

	hash_iterate(bgp_evpn->vni_svi_hash,
		     (void (*)(struct hash_bucket *,
			       void *))bgp_evpn_show_vni_svi_hash,
		     vty);

	return CMD_SUCCESS;
}

DEFPY(show_bgp_l2vpn_evpn_es_evi,
      show_bgp_l2vpn_evpn_es_evi_cmd,
      "show bgp l2vpn evpn es-evi [vni (1-16777215)$vni] [json$uj] [detail$detail]",
      SHOW_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "ES per EVI\n"
      "VxLAN Network Identifier\n"
      "VNI\n"
      JSON_STR
      "Detailed information\n")
{
	if (vni)
		bgp_evpn_es_evi_show_vni(vty, vni, !!uj, !!detail);
	else
		bgp_evpn_es_evi_show(vty, !!uj, !!detail);

	return CMD_SUCCESS;
}

DEFPY(show_bgp_l2vpn_evpn_es,
      show_bgp_l2vpn_evpn_es_cmd,
      "show bgp l2vpn evpn es [NAME$esi_str|detail$detail] [json$uj]",
      SHOW_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "Ethernet Segment\n"
      "ES ID\n"
      "Detailed information\n"
      JSON_STR)
{
	esi_t esi;

	if (esi_str) {
		if (!str_to_esi(esi_str, &esi)) {
			vty_out(vty, "%% Malformed ESI\n");
			return CMD_WARNING;
		}
		bgp_evpn_es_show_esi(vty, &esi, uj);
	} else {

		bgp_evpn_es_show(vty, uj, !!detail);
	}

	return CMD_SUCCESS;
}

DEFPY(show_bgp_l2vpn_evpn_es_vrf, show_bgp_l2vpn_evpn_es_vrf_cmd,
      "show bgp l2vpn evpn es-vrf [NAME$esi_str] [json$uj]",
      SHOW_STR BGP_STR L2VPN_HELP_STR EVPN_HELP_STR
      "Ethernet Segment\n"
      "ES ID\n" JSON_STR)
{
	esi_t esi;

	if (esi_str) {
		if (!str_to_esi(esi_str, &esi)) {
			vty_out(vty, "%% Malformed ESI\n");
			return CMD_WARNING;
		}
		bgp_evpn_es_vrf_show_esi(vty, &esi, uj);
	} else {

		bgp_evpn_es_vrf_show(vty, uj, NULL);
	}

	return CMD_SUCCESS;
}

DEFPY(show_bgp_l2vpn_evpn_nh,
      show_bgp_l2vpn_evpn_nh_cmd,
      "show bgp l2vpn evpn next-hops [json$uj]",
      SHOW_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "Nexthops\n"
      JSON_STR)
{
	bgp_evpn_nh_show(vty, uj);

	return CMD_SUCCESS;
}

/*
 * Display EVPN neighbor summary.
 */
DEFUN(show_bgp_l2vpn_evpn_summary, show_bgp_l2vpn_evpn_summary_cmd,
      "show bgp [vrf VRFNAME] l2vpn evpn summary [established|failed] [<neighbor <A.B.C.D|X:X::X:X|WORD>|remote-as <(1-4294967295)|internal|external>>] [terse] [wide] [json]",
      SHOW_STR BGP_STR
      "bgp vrf\n"
      "vrf name\n" L2VPN_HELP_STR EVPN_HELP_STR
      "Summary of BGP neighbor status\n"
      "Show only sessions in Established state\n"
      "Show only sessions not in Established state\n"
      "Show only the specified neighbor session\n"
      "Neighbor to display information about\n"
      "Neighbor to display information about\n"
      "Neighbor on BGP configured interface\n"
      "Show only the specified remote AS sessions\n"
      "AS number\n"
      "Internal (iBGP) AS sessions\n"
      "External (eBGP) AS sessions\n"
      "Shorten the information on BGP instances\n"
      "Increase table width for longer output\n" JSON_STR)
{
	int idx_vrf = 0;
	int idx = 0;
	char *vrf = NULL;
	char *neighbor = NULL;
	as_t as = 0; /* 0 means AS filter not set */
	int as_type = AS_UNSPECIFIED;
	uint16_t show_flags = 0;

	if (argv_find(argv, argc, "vrf", &idx_vrf))
		vrf = argv[++idx_vrf]->arg;

	if (argv_find(argv, argc, "failed", &idx))
		SET_FLAG(show_flags, BGP_SHOW_OPT_FAILED);

	if (argv_find(argv, argc, "established", &idx))
		SET_FLAG(show_flags, BGP_SHOW_OPT_ESTABLISHED);


	if (argv_find(argv, argc, "neighbor", &idx))
		neighbor = argv[idx + 1]->arg;

	if (argv_find(argv, argc, "remote-as", &idx)) {
		if (argv[idx + 1]->arg[0] == 'i')
			as_type = AS_INTERNAL;
		else if (argv[idx + 1]->arg[0] == 'e')
			as_type = AS_EXTERNAL;
		else
			as = (as_t)atoi(argv[idx + 1]->arg);
	}

	if (argv_find(argv, argc, "terse", &idx))
		SET_FLAG(show_flags, BGP_SHOW_OPT_TERSE);

	if (argv_find(argv, argc, "wide", &idx))
		SET_FLAG(show_flags, BGP_SHOW_OPT_WIDE);

	if (use_json(argc, argv))
		SET_FLAG(show_flags, BGP_SHOW_OPT_JSON);

	return bgp_show_summary_vty(vty, vrf, AFI_L2VPN, SAFI_EVPN, neighbor,
				    as_type, as, show_flags);
}

static int bgp_evpn_cli_parse_type_cmp(int *type, const char *type_str)
{
	if ((strncmp(type_str, "ma", 2) == 0) || (strmatch(type_str, "2")))
		*type = BGP_EVPN_MAC_IP_ROUTE;
	else if ((strncmp(type_str, "mu", 2) == 0) || (strmatch(type_str, "3")))
		*type = BGP_EVPN_IMET_ROUTE;
	else if ((strncmp(type_str, "es", 2) == 0) || (strmatch(type_str, "4")))
		*type = BGP_EVPN_ES_ROUTE;
	else if ((strncmp(type_str, "ea", 2) == 0) || (strmatch(type_str, "1")))
		*type = BGP_EVPN_AD_ROUTE;
	else if ((strncmp(type_str, "p", 1) == 0) || (strmatch(type_str, "5")))
		*type = BGP_EVPN_IP_PREFIX_ROUTE;
	else
		return -1;

	return 0;
}

int bgp_evpn_cli_parse_type(int *type, struct cmd_token **argv, int argc)
{
	int type_idx = 0;

	if (argv_find(argv, argc, "type", &type_idx)) {
		/* Specific type is requested */
		if (bgp_evpn_cli_parse_type_cmp(type,
						argv[type_idx + 1]->arg) != 0)
			return -1;
	}

	return 0;
}

/*
 * Display global EVPN routing table.
 */
DEFUN(show_bgp_l2vpn_evpn_route,
      show_bgp_l2vpn_evpn_route_cmd,
      "show bgp l2vpn evpn route [detail] [type "EVPN_TYPE_ALL_LIST"] ["BGP_SELF_ORIG_CMD_STR"] [json]",
      SHOW_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      EVPN_RT_HELP_STR
      "Display Detailed Information\n"
      EVPN_TYPE_HELP_STR
      EVPN_TYPE_ALL_LIST_HELP_STR
      BGP_SELF_ORIG_HELP_STR
      JSON_STR)
{
	struct bgp *bgp;
	int detail = 0;
	int type = 0;
	bool uj = false;
	int arg_idx = 0;
	bool self_orig = false;
	json_object *json = NULL;

	uj = use_json(argc, argv);

	bgp = bgp_get_evpn();
	if (!bgp)
		return CMD_WARNING;

	if (uj)
		json = json_object_new_object();

	if (bgp_evpn_cli_parse_type(&type, argv, argc) < 0)
		return CMD_WARNING;

	if (argv_find(argv, argc, "detail", &detail))
		detail = 1;

	if (argv_find(argv, argc, BGP_SELF_ORIG_CMD_STR, &arg_idx))
		self_orig = true;

	evpn_show_all_routes(vty, bgp, type, json, detail, self_orig);

	/*
	 * This is an extremely expensive operation at scale
	 * and as such we need to save as much time as is
	 * possible.
	 */
	if (uj)
		vty_json_no_pretty(vty, json);

	return CMD_SUCCESS;
}

/*
 * Display global EVPN routing table for specific RD.
 */
DEFUN(show_bgp_l2vpn_evpn_route_rd,
      show_bgp_l2vpn_evpn_route_rd_cmd,
      "show bgp l2vpn evpn route rd <ASN:NN_OR_IP-ADDRESS:NN|all> [type "EVPN_TYPE_ALL_LIST"] [json]",
      SHOW_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      EVPN_RT_HELP_STR
      EVPN_RT_DIST_HELP_STR
      EVPN_ASN_IP_HELP_STR
      "All VPN Route Distinguishers\n"
      EVPN_TYPE_HELP_STR
      EVPN_TYPE_ALL_LIST_HELP_STR
      JSON_STR)
{
	struct bgp *bgp;
	int ret = 0;
	struct prefix_rd prd;
	int type = 0;
	bool uj = false;
	json_object *json = NULL;
	int idx_ext_community = 0;
	int rd_all = 0;

	bgp = bgp_get_evpn();
	if (!bgp)
		return CMD_WARNING;

	/* check if we need json output */
	uj = use_json(argc, argv);
	if (uj)
		json = json_object_new_object();

	if (!argv_find(argv, argc, "all", &rd_all)) {
		/* get the RD */
		if (argv_find(argv, argc, "ASN:NN_OR_IP-ADDRESS:NN",
			      &idx_ext_community)) {
			ret = str2prefix_rd(argv[idx_ext_community]->arg, &prd);
			if (!ret) {
				vty_out(vty,
					"%% Malformed Route Distinguisher\n");
				return CMD_WARNING;
			}
		}
	}

	if (bgp_evpn_cli_parse_type(&type, argv, argc) < 0)
		return CMD_WARNING;

	if (rd_all)
		evpn_show_all_routes(vty, bgp, type, json, 1, false);
	else
		evpn_show_route_rd(vty, bgp, &prd, type, json);

	if (uj)
		vty_json(vty, json);

	return CMD_SUCCESS;
}

/*
 * Display global EVPN routing table for specific RD and MACIP.
 */
DEFUN(show_bgp_l2vpn_evpn_route_rd_macip,
      show_bgp_l2vpn_evpn_route_rd_macip_cmd,
      "show bgp l2vpn evpn route rd <ASN:NN_OR_IP-ADDRESS:NN|all> mac WORD [ip WORD] [json]",
      SHOW_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      EVPN_RT_HELP_STR
      EVPN_RT_DIST_HELP_STR
      EVPN_ASN_IP_HELP_STR
      "All VPN Route Distinguishers\n"
      "MAC\n"
      "MAC address (e.g., 00:e0:ec:20:12:62)\n"
      "IP\n"
      "IP address (IPv4 or IPv6)\n"
      JSON_STR)
{
	struct bgp *bgp;
	int ret = 0;
	struct prefix_rd prd;
	struct ethaddr mac;
	struct ipaddr ip;
	int idx_ext_community = 0;
	int mac_idx = 0;
	int ip_idx = 0;
	bool uj = false;
	json_object *json = NULL;
	int rd_all = 0;

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
	if (!argv_find(argv, argc, "all", &rd_all)) {
		if (argv_find(argv, argc, "ASN:NN_OR_IP-ADDRESS:NN",
			      &idx_ext_community)) {
			ret = str2prefix_rd(argv[idx_ext_community]->arg, &prd);
			if (!ret) {
				vty_out(vty,
					"%% Malformed Route Distinguisher\n");
				return CMD_WARNING;
			}
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

	if (rd_all)
		evpn_show_route_rd_all_macip(vty, bgp, &mac, &ip, json);
	else
		evpn_show_route_rd_macip(vty, bgp, &prd, &mac, &ip, json);

	if (uj)
		vty_json(vty, json);

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
      EVPN_RT_HELP_STR
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

	if (uj)
		vty_json(vty, json);

	return CMD_SUCCESS;
}


/*
 * Display per-VNI EVPN routing table.
 */
DEFUN(show_bgp_l2vpn_evpn_route_vni, show_bgp_l2vpn_evpn_route_vni_cmd,
      "show bgp l2vpn evpn route vni " CMD_VNI_RANGE " [<type <ead|1|macip|2|multicast|3> | vtep A.B.C.D>] [json]",
      SHOW_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      EVPN_RT_HELP_STR
      "VXLAN Network Identifier\n"
      "VNI number\n"
      EVPN_TYPE_HELP_STR
      EVPN_TYPE_1_HELP_STR
      EVPN_TYPE_1_HELP_STR
      EVPN_TYPE_2_HELP_STR
      EVPN_TYPE_2_HELP_STR
      EVPN_TYPE_3_HELP_STR
      EVPN_TYPE_3_HELP_STR
      "Remote VTEP\n"
      "Remote VTEP IP address\n"
      JSON_STR)
{
	vni_t vni;
	struct bgp *bgp;
	struct in_addr vtep_ip;
	int type = 0;
	int idx = 0;
	int vtep_idx = 0;
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

	if (bgp_evpn_cli_parse_type(&type, argv, argc) < 0)
		return CMD_WARNING;

	if (argv_find(argv, argc, "vtep", &vtep_idx)) {
		if (!inet_aton(argv[vtep_idx + 1]->arg, &vtep_ip)) {
			vty_out(vty, "%% Malformed VTEP IP address\n");
			return CMD_WARNING;
		}
	}

	evpn_show_routes_vni(vty, bgp, vni, type, false, vtep_ip, json);

	if (uj)
		vty_json(vty, json);

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
      EVPN_RT_HELP_STR
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

	if (uj)
		vty_json(vty, json);

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
      EVPN_RT_HELP_STR
      "VXLAN Network Identifier\n"
      "VNI number\n"
      EVPN_TYPE_3_HELP_STR
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

	if (uj)
		vty_json(vty, json);

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
      EVPN_RT_HELP_STR
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

	evpn_show_routes_vni_all(vty, bgp, 0, false, vtep_ip, json, da);

	if (uj) {
		vty_json(vty, json);
		json_object_free(json);
	}

	return CMD_SUCCESS;
}

/*
 * Display per-VNI EVPN ALL routing tables - for all VNIs.
 */
DEFPY(show_bgp_vni_all,
      show_bgp_vni_all_cmd,
      "show bgp vni all [vtep A.B.C.D$addr] [detail$detail] [json$uj]",
      SHOW_STR
      BGP_STR
      VNI_HELP_STR
      VNI_ALL_HELP_STR
      VTEP_HELP_STR
      VTEP_IP_HELP_STR
      DETAIL_HELP_STR
      JSON_STR)
{
	struct bgp *bgp;
	json_object *json = NULL;

	bgp = bgp_get_evpn();
	if (!bgp)
		return CMD_WARNING;

	/* check if we need json output */
	if (uj)
		json = json_object_new_object();

	evpn_show_routes_vni_all_type_all(vty, bgp, addr, json, !!detail);

	if (uj)
		vty_json(vty, json);

	return CMD_SUCCESS;
}

/*
 * Display per-VNI EVPN EAD routing table - for all VNIs.
 */
DEFPY(show_bgp_vni_all_ead,
      show_bgp_vni_all_ead_cmd,
      "show bgp vni all type <1|ead> [vtep A.B.C.D$addr] [<detail$detail|json$uj>]",
      SHOW_STR
      BGP_STR
      VNI_HELP_STR
      VNI_ALL_HELP_STR
      EVPN_TYPE_HELP_STR
      EVPN_TYPE_1_HELP_STR
      EVPN_TYPE_1_HELP_STR
      VTEP_HELP_STR
      VTEP_IP_HELP_STR
      DETAIL_HELP_STR
      JSON_STR)
{
	struct bgp *bgp;
	json_object *json = NULL;

	bgp = bgp_get_evpn();
	if (!bgp)
		return CMD_WARNING;

	/* check if we need json output */
	if (uj)
		json = json_object_new_object();

	evpn_show_routes_vni_all(vty, bgp, BGP_EVPN_AD_ROUTE, false, addr, json,
				 !!detail);

	if (uj)
		vty_json(vty, json);

	return CMD_SUCCESS;
}

/*
 * Display per-VNI EVPN MAC routing table - for all VNIs.
 */
DEFPY(show_bgp_vni_all_macip_mac,
      show_bgp_vni_all_macip_mac_cmd,
      "show bgp vni all type <2|macip> mac [vtep A.B.C.D$addr] [<detail$detail|json$uj>]",
      SHOW_STR
      BGP_STR
      VNI_HELP_STR
      VNI_ALL_HELP_STR
      EVPN_TYPE_HELP_STR
      EVPN_TYPE_2_HELP_STR
      EVPN_TYPE_2_HELP_STR
      "MAC Table\n"
      VTEP_HELP_STR
      VTEP_IP_HELP_STR
      DETAIL_HELP_STR
      JSON_STR)
{
	struct bgp *bgp;
	json_object *json = NULL;

	bgp = bgp_get_evpn();
	if (!bgp)
		return CMD_WARNING;

	/* check if we need json output */
	if (uj)
		json = json_object_new_object();

	evpn_show_routes_vni_all(vty, bgp, BGP_EVPN_MAC_IP_ROUTE, true, addr,
				 json, !!detail);

	if (uj)
		vty_json(vty, json);

	return CMD_SUCCESS;
}

/*
 * Display per-VNI EVPN IP routing table - for all VNIs.
 */
DEFPY(show_bgp_vni_all_macip_ip,
      show_bgp_vni_all_macip_ip_cmd,
      "show bgp vni all type <2|macip> ip [vtep A.B.C.D$addr] [<detail$detail|json$uj>]",
      SHOW_STR
      BGP_STR
      VNI_HELP_STR
      VNI_ALL_HELP_STR
      EVPN_TYPE_HELP_STR
      EVPN_TYPE_2_HELP_STR
      EVPN_TYPE_2_HELP_STR
      "IP Table\n"
      VTEP_HELP_STR
      VTEP_IP_HELP_STR
      DETAIL_HELP_STR
      JSON_STR)
{
	struct bgp *bgp;
	json_object *json = NULL;

	bgp = bgp_get_evpn();
	if (!bgp)
		return CMD_WARNING;

	/* check if we need json output */
	if (uj)
		json = json_object_new_object();

	evpn_show_routes_vni_all(vty, bgp, BGP_EVPN_MAC_IP_ROUTE, false, addr,
				 json, !!detail);

	if (uj)
		vty_json(vty, json);

	return CMD_SUCCESS;
}

/*
 * Display per-VNI EVPN Multicast routing table - for all VNIs.
 */
DEFPY(show_bgp_vni_all_imet,
      show_bgp_vni_all_imet_cmd,
      "show bgp vni all type <3|multicast> [vtep A.B.C.D$addr] [<detail$detail|json$uj>]",
      SHOW_STR
      BGP_STR
      VNI_HELP_STR
      VNI_ALL_HELP_STR
      EVPN_TYPE_HELP_STR
      EVPN_TYPE_3_HELP_STR
      EVPN_TYPE_3_HELP_STR
      VTEP_HELP_STR
      VTEP_IP_HELP_STR
      DETAIL_HELP_STR
      JSON_STR)
{
	struct bgp *bgp;
	json_object *json = NULL;

	bgp = bgp_get_evpn();
	if (!bgp)
		return CMD_WARNING;

	/* check if we need json output */
	if (uj)
		json = json_object_new_object();

	evpn_show_routes_vni_all(vty, bgp, BGP_EVPN_IMET_ROUTE, false, addr,
				 json, !!detail);

	if (uj)
		vty_json(vty, json);

	return CMD_SUCCESS;
}

/*
 * Display per-VNI EVPN ALL routing tables - for select VNI
 */
DEFPY(show_bgp_vni,
      show_bgp_vni_cmd,
      "show bgp vni "CMD_VNI_RANGE"$vni [vtep A.B.C.D$addr] [json$uj]",
      SHOW_STR
      BGP_STR
      VNI_HELP_STR
      VNI_NUM_HELP_STR
      VTEP_HELP_STR
      VTEP_IP_HELP_STR
      JSON_STR)
{
	struct bgp *bgp;
	json_object *json = NULL;
	json_object *json_mac = NULL;

	bgp = bgp_get_evpn();
	if (!bgp)
		return CMD_WARNING;

	/* check if we need json output */
	if (uj) {
		json = json_object_new_object();
		json_mac = json_object_new_object();
	}

	evpn_show_routes_vni(vty, bgp, vni, 0, false, addr, json);

	if (!uj)
		vty_out(vty, "\n\nMAC Table:\n\n");

	evpn_show_routes_vni(vty, bgp, vni, 0, true, addr, json_mac);

	if (uj) {
		json_object_object_add(json, "macTable", json_mac);
		vty_json(vty, json);
	}

	return CMD_SUCCESS;
}

/*
 * Display per-VNI EVPN EAD routing table - for select VNI
 */
DEFPY(show_bgp_vni_ead,
      show_bgp_vni_ead_cmd,
      "show bgp vni "CMD_VNI_RANGE"$vni type <1|ead> [vtep A.B.C.D$addr] [json$uj]",
      SHOW_STR
      BGP_STR
      VNI_HELP_STR
      VNI_NUM_HELP_STR
      EVPN_TYPE_HELP_STR
      EVPN_TYPE_1_HELP_STR
      EVPN_TYPE_1_HELP_STR
      VTEP_HELP_STR
      VTEP_IP_HELP_STR
      JSON_STR)
{
	struct bgp *bgp;
	json_object *json = NULL;

	bgp = bgp_get_evpn();
	if (!bgp)
		return CMD_WARNING;

	/* check if we need json output */
	if (uj)
		json = json_object_new_object();

	evpn_show_routes_vni(vty, bgp, vni, BGP_EVPN_AD_ROUTE, false, addr,
			     json);

	if (uj)
		vty_json(vty, json);

	return CMD_SUCCESS;
}

/*
 * Display per-VNI EVPN MAC-IP MAC routing table - for select VNI
 */
DEFPY(show_bgp_vni_macip_mac,
      show_bgp_vni_macip_mac_cmd,
      "show bgp vni "CMD_VNI_RANGE"$vni type <2|macip> mac [vtep A.B.C.D$addr] [json$uj]",
      SHOW_STR
      BGP_STR
      VNI_HELP_STR
      VNI_NUM_HELP_STR
      EVPN_TYPE_HELP_STR
      EVPN_TYPE_2_HELP_STR
      EVPN_TYPE_2_HELP_STR
      "MAC Table\n"
      VTEP_HELP_STR
      VTEP_IP_HELP_STR
      JSON_STR)
{
	struct bgp *bgp;
	json_object *json = NULL;

	bgp = bgp_get_evpn();
	if (!bgp)
		return CMD_WARNING;

	/* check if we need json output */
	if (uj)
		json = json_object_new_object();

	evpn_show_routes_vni(vty, bgp, vni, BGP_EVPN_MAC_IP_ROUTE, true, addr,
			     json);

	if (uj)
		vty_json(vty, json);

	return CMD_SUCCESS;
}

/*
 * Display per-VNI EVPN MAC-IP IP routing table - for select VNI
 */
DEFPY(show_bgp_vni_macip_ip,
      show_bgp_vni_macip_ip_cmd,
      "show bgp vni "CMD_VNI_RANGE"$vni type <2|macip> ip [vtep A.B.C.D$addr] [json$uj]",
      SHOW_STR
      BGP_STR
      VNI_HELP_STR
      VNI_NUM_HELP_STR
      EVPN_TYPE_HELP_STR
      EVPN_TYPE_2_HELP_STR
      EVPN_TYPE_2_HELP_STR
      "IP Table\n"
      VTEP_HELP_STR
      VTEP_IP_HELP_STR
      JSON_STR)
{
	struct bgp *bgp;
	json_object *json = NULL;

	bgp = bgp_get_evpn();
	if (!bgp)
		return CMD_WARNING;

	/* check if we need json output */
	if (uj)
		json = json_object_new_object();

	evpn_show_routes_vni(vty, bgp, vni, BGP_EVPN_MAC_IP_ROUTE, false, addr,
			     json);

	if (uj)
		vty_json(vty, json);

	return CMD_SUCCESS;
}

/*
 * Display per-VNI EVPN Multicast routing table - for select VNI
 */
DEFPY(show_bgp_vni_imet,
      show_bgp_vni_imet_cmd,
      "show bgp vni "CMD_VNI_RANGE"$vni type <3|multicast> [vtep A.B.C.D$addr] [json$uj]",
      SHOW_STR
      BGP_STR
      VNI_HELP_STR
      VNI_NUM_HELP_STR
      EVPN_TYPE_HELP_STR
      EVPN_TYPE_3_HELP_STR
      EVPN_TYPE_3_HELP_STR
      VTEP_HELP_STR
      VTEP_IP_HELP_STR
      JSON_STR)
{
	struct bgp *bgp;
	json_object *json = NULL;

	bgp = bgp_get_evpn();
	if (!bgp)
		return CMD_WARNING;

	/* check if we need json output */
	if (uj)
		json = json_object_new_object();

	evpn_show_routes_vni(vty, bgp, vni, BGP_EVPN_IMET_ROUTE, false, addr,
			     json);

	if (uj)
		vty_json(vty, json);

	return CMD_SUCCESS;
}

/*
 * Display per-VNI EVPN MACIP MAC routing table - for select VNI & MAC
 */
DEFPY(show_bgp_vni_macip_mac_addr,
      show_bgp_vni_macip_mac_addr_cmd,
      "show bgp vni "CMD_VNI_RANGE"$vni type <2|macip> mac X:X:X:X:X:X [json$uj]",
      SHOW_STR
      BGP_STR
      VNI_HELP_STR
      VNI_NUM_HELP_STR
      EVPN_TYPE_HELP_STR
      EVPN_TYPE_2_HELP_STR
      EVPN_TYPE_2_HELP_STR
      "MAC Table\n"
      MAC_STR
      JSON_STR)
{
	struct bgp *bgp;
	json_object *json = NULL;

	bgp = bgp_get_evpn();
	if (!bgp)
		return CMD_WARNING;

	/* check if we need json output */
	if (uj)
		json = json_object_new_object();

	evpn_show_route_vni_macip(vty, bgp, vni, &mac->eth_addr, NULL, json);

	if (uj)
		vty_json(vty, json);

	return CMD_SUCCESS;
}

/*
 * Display per-VNI EVPN MACIP IP routing table - for select VNI & IP
 */
DEFPY(show_bgp_vni_macip_ip_addr, show_bgp_vni_macip_ip_addr_cmd,
      "show bgp vni " CMD_VNI_RANGE
      "$vni type <2|macip> ip <A.B.C.D|X:X::X:X> [json$uj]",
      SHOW_STR BGP_STR VNI_HELP_STR VNI_NUM_HELP_STR EVPN_TYPE_HELP_STR
	      EVPN_TYPE_2_HELP_STR EVPN_TYPE_2_HELP_STR
      "IP Table\n" IP_ADDR_STR IP6_ADDR_STR JSON_STR)
{
	struct bgp *bgp;
	json_object *json = NULL;
	struct ipaddr ip_addr = {.ipa_type = IPADDR_NONE};

	bgp = bgp_get_evpn();
	if (!bgp)
		return CMD_WARNING;

	/* check if we need json output */
	if (uj)
		json = json_object_new_object();

	if (sockunion_family(ip) == AF_INET) {
		ip_addr.ipa_type = IPADDR_V4;
		ip_addr.ipaddr_v4.s_addr = sockunion2ip(ip);
	} else {
		ip_addr.ipa_type = IPADDR_V6;
		memcpy(&ip_addr.ipaddr_v6, &ip->sin6.sin6_addr,
		       sizeof(struct in6_addr));
	}
	evpn_show_route_vni_macip(vty, bgp, vni, NULL, &ip_addr, json);

	if (uj)
		vty_json(vty, json);

	return CMD_SUCCESS;
}

DEFPY_HIDDEN(
	show_bgp_l2vpn_evpn_route_mac_ip_evi_es,
	show_bgp_l2vpn_evpn_route_mac_ip_evi_es_cmd,
	"show bgp l2vpn evpn route mac-ip-evi-es [NAME$esi_str|detail$detail] [json$uj]",
	SHOW_STR BGP_STR L2VPN_HELP_STR EVPN_HELP_STR
	"EVPN route information\n"
	"MAC IP routes in the EVI tables linked to the ES\n"
	"ES ID\n"
	"Detailed information\n" JSON_STR)
{
	esi_t esi;
	esi_t *esi_p;
	json_object *json = NULL;

	if (esi_str) {
		if (!str_to_esi(esi_str, &esi)) {
			vty_out(vty, "%% Malformed ESI\n");
			return CMD_WARNING;
		}
		esi_p = &esi;
	} else {
		esi_p = NULL;
	}

	if (uj)
		json = json_object_new_object();
	bgp_evpn_show_routes_mac_ip_evi_es(vty, esi_p, json, !!detail);
	if (uj)
		vty_json(vty, json);

	return CMD_SUCCESS;
}

DEFPY_HIDDEN(
	show_bgp_l2vpn_evpn_route_mac_ip_global_es,
	show_bgp_l2vpn_evpn_route_mac_ip_global_es_cmd,
	"show bgp l2vpn evpn route mac-ip-global-es [NAME$esi_str|detail$detail] [json$uj]",
	SHOW_STR BGP_STR L2VPN_HELP_STR EVPN_HELP_STR
	"EVPN route information\n"
	"MAC IP routes in the global table linked to the ES\n"
	"ES ID\n"
	"Detailed information\n" JSON_STR)
{
	esi_t esi;
	esi_t *esi_p;
	json_object *json = NULL;

	if (esi_str) {
		if (!str_to_esi(esi_str, &esi)) {
			vty_out(vty, "%% Malformed ESI\n");
			return CMD_WARNING;
		}
		esi_p = &esi;
	} else {
		esi_p = NULL;
	}

	if (uj)
		json = json_object_new_object();
	bgp_evpn_show_routes_mac_ip_global_es(vty, esi_p, json, !!detail);
	if (uj)
		vty_json(vty, json);

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

	if (uj)
		vty_json(vty, json);

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

	if (uj)
		vty_json(vty, json);

	return CMD_SUCCESS;
}

DEFPY_HIDDEN(test_es_add,
      test_es_add_cmd,
      "[no$no] test es NAME$esi_str [state NAME$state_str]",
      NO_STR
      "Test\n"
      "Ethernet-segment\n"
      "Ethernet-Segment Identifier\n"
      "ES link state\n"
      "up|down\n"
)
{
	int ret = 0;
	esi_t esi;
	struct bgp *bgp;
	struct in_addr vtep_ip;
	bool oper_up;

	bgp = bgp_get_evpn();
	if (!bgp) {
		vty_out(vty, "%% EVPN BGP instance not yet created\n");
		return CMD_WARNING;
	}

	if (!str_to_esi(esi_str, &esi)) {
		vty_out(vty, "%% Malformed ESI\n");
		return CMD_WARNING;
	}

	if (no) {
		ret = bgp_evpn_local_es_del(bgp, &esi);
		if (ret == -1) {
			vty_out(vty, "%% Failed to delete ES\n");
			return CMD_WARNING;
		}
	} else {
		if (state_str && !strcmp(state_str, "up"))
			oper_up = true;
		else
			oper_up = false;
		vtep_ip = bgp->router_id;

		ret = bgp_evpn_local_es_add(bgp, &esi, vtep_ip, oper_up,
					    EVPN_MH_DF_PREF_MIN, false);
		if (ret == -1) {
			vty_out(vty, "%% Failed to add ES\n");
			return CMD_WARNING;
		}
	}
	return CMD_SUCCESS;
}

DEFPY_HIDDEN(test_es_vni_add,
      test_es_vni_add_cmd,
      "[no$no] test es NAME$esi_str vni (1-16777215)$vni",
      NO_STR
      "Test\n"
      "Ethernet-segment\n"
      "Ethernet-Segment Identifier\n"
      "VNI\n"
      "1-16777215\n"
)
{
	int ret = 0;
	esi_t esi;
	struct bgp *bgp;

	bgp = bgp_get_evpn();
	if (!bgp) {
		vty_out(vty, "%% EVPN BGP instance not yet created\n");
		return CMD_WARNING;
	}

	if (!str_to_esi(esi_str, &esi)) {
		vty_out(vty, "%% Malformed ESI\n");
		return CMD_WARNING;
	}

	if (no) {
		ret = bgp_evpn_local_es_evi_del(bgp, &esi, vni);
		if (ret == -1) {
			vty_out(vty, "%% Failed to deref ES VNI\n");
			return CMD_WARNING;
		}
	} else {
		ret = bgp_evpn_local_es_evi_add(bgp, &esi, vni);
		if (ret == -1) {
			vty_out(vty, "%% Failed to ref ES VNI\n");
			return CMD_WARNING;
		}
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
	     "show bgp evpn route [detail] [type <macip|2|multicast|3>]",
	     SHOW_STR BGP_STR EVPN_HELP_STR
	     EVPN_RT_HELP_STR
	     "Display Detailed Information\n"
	     EVPN_TYPE_HELP_STR
	     EVPN_TYPE_2_HELP_STR
	     EVPN_TYPE_2_HELP_STR
	     EVPN_TYPE_3_HELP_STR
	     EVPN_TYPE_3_HELP_STR)

ALIAS_HIDDEN(
	show_bgp_l2vpn_evpn_route_rd, show_bgp_evpn_route_rd_cmd,
	"show bgp evpn route rd ASN:NN_OR_IP-ADDRESS:NN [type <macip|2|multicast|3>]",
	SHOW_STR BGP_STR EVPN_HELP_STR
	EVPN_RT_HELP_STR
	EVPN_RT_DIST_HELP_STR
	EVPN_ASN_IP_HELP_STR
	EVPN_TYPE_HELP_STR
	EVPN_TYPE_2_HELP_STR
	EVPN_TYPE_2_HELP_STR
	EVPN_TYPE_3_HELP_STR
	EVPN_TYPE_3_HELP_STR)

ALIAS_HIDDEN(
	show_bgp_l2vpn_evpn_route_rd_macip, show_bgp_evpn_route_rd_macip_cmd,
	"show bgp evpn route rd ASN:NN_OR_IP-ADDRESS:NN mac WORD [ip WORD]",
	SHOW_STR BGP_STR EVPN_HELP_STR
	EVPN_RT_HELP_STR
	EVPN_RT_DIST_HELP_STR
	EVPN_ASN_IP_HELP_STR
	"MAC\n"
	"MAC address (e.g., 00:e0:ec:20:12:62)\n"
	"IP\n"
	"IP address (IPv4 or IPv6)\n")

ALIAS_HIDDEN(
	show_bgp_l2vpn_evpn_route_vni, show_bgp_evpn_route_vni_cmd,
	"show bgp evpn route vni " CMD_VNI_RANGE " [<type <macip|2|multicast|3> | vtep A.B.C.D>]",
	SHOW_STR BGP_STR EVPN_HELP_STR
	EVPN_RT_HELP_STR
	"VXLAN Network Identifier\n"
	"VNI number\n"
	EVPN_TYPE_HELP_STR
	EVPN_TYPE_2_HELP_STR
	EVPN_TYPE_2_HELP_STR
	EVPN_TYPE_3_HELP_STR
	EVPN_TYPE_3_HELP_STR
	"Remote VTEP\n"
	"Remote VTEP IP address\n")

ALIAS_HIDDEN(show_bgp_l2vpn_evpn_route_vni_macip,
	     show_bgp_evpn_route_vni_macip_cmd,
	     "show bgp evpn route vni " CMD_VNI_RANGE " mac WORD [ip WORD]",
	     SHOW_STR BGP_STR EVPN_HELP_STR
	     EVPN_RT_HELP_STR
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
	     EVPN_RT_HELP_STR
	     "VXLAN Network Identifier\n"
	     "VNI number\n"
	     EVPN_TYPE_3_HELP_STR
	     "Originating Router IP address\n")

ALIAS_HIDDEN(show_bgp_l2vpn_evpn_route_vni_all, show_bgp_evpn_route_vni_all_cmd,
	     "show bgp evpn route vni all [detail] [vtep A.B.C.D]",
	     SHOW_STR BGP_STR EVPN_HELP_STR
	     EVPN_RT_HELP_STR
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
       EVPN_RT_DIST_HELP_STR
       EVPN_ASN_IP_HELP_STR)
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
	evpn_configure_vrf_rd(bgp_vrf, &prd, argv[1]->arg);
	return CMD_SUCCESS;
}

DEFUN (no_bgp_evpn_vrf_rd,
       no_bgp_evpn_vrf_rd_cmd,
       "no rd ASN:NN_OR_IP-ADDRESS:NN",
       NO_STR
       EVPN_RT_DIST_HELP_STR
       EVPN_ASN_IP_HELP_STR)
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
       EVPN_RT_DIST_HELP_STR)
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
       EVPN_RT_DIST_HELP_STR
       EVPN_ASN_IP_HELP_STR)
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
	evpn_configure_rd(bgp, vpn, &prd, argv[1]->arg);
	return CMD_SUCCESS;
}

DEFUN (no_bgp_evpn_vni_rd,
       no_bgp_evpn_vni_rd_cmd,
       "no rd ASN:NN_OR_IP-ADDRESS:NN",
       NO_STR
       EVPN_RT_DIST_HELP_STR
       EVPN_ASN_IP_HELP_STR)
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
       EVPN_RT_DIST_HELP_STR)
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
static bool bgp_evpn_rt_matches_existing(struct list *rtl,
					 struct ecommunity *ecomtarget)
{
	struct listnode *node;
	struct ecommunity *ecom;

	for (ALL_LIST_ELEMENTS_RO(rtl, node, ecom)) {
		if (ecommunity_match(ecom, ecomtarget))
			return true;
	}

	return false;
}

/*
 * L3 RT version of above.
 */
static bool bgp_evpn_vrf_rt_matches_existing(struct list *rtl,
					     struct ecommunity *ecomtarget)
{
	struct listnode *node;
	struct vrf_route_target *l3rt;

	for (ALL_LIST_ELEMENTS_RO(rtl, node, l3rt)) {
		if (ecommunity_match(l3rt->ecom, ecomtarget))
			return true;
	}

	return false;
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
	int idx_vrf = 3;
	const char *name = NULL;
	struct bgp *bgp = NULL;
	struct listnode *node = NULL;
	struct bgpevpn *vpn = NULL;
	struct vrf_route_target *l3rt;
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
	if (strmatch(name, VRF_DEFAULT_NAME))
		bgp = bgp_get_default();

	if (!bgp) {
		if (!uj)
			vty_out(vty, "BGP instance for VRF %s not found\n",
				name);
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
		vty_out(vty, "  Local-Ip: %pI4\n", &bgp->originator_ip);
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
		for (ALL_LIST_ELEMENTS_RO(bgp->vrf_export_rtl, node, l3rt))
			vty_out(vty, "%s  ", ecommunity_str(l3rt->ecom));
		vty_out(vty, "\n");
		vty_out(vty, "  Import-RTs:\n");
		vty_out(vty, "    ");
		for (ALL_LIST_ELEMENTS_RO(bgp->vrf_import_rtl, node, l3rt))
			vty_out(vty, "%s  ", ecommunity_str(l3rt->ecom));
		vty_out(vty, "\n");
		vty_out(vty, "  RD: ");
		vty_out(vty, BGP_RD_AS_FORMAT(bgp->asnotation), &bgp->vrf_prd);
		vty_out(vty, "\n");
	} else {
		json_object_string_add(json, "vrf", name);
		json_object_string_addf(json, "local-ip", "%pI4",
					&bgp->originator_ip);
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
		for (ALL_LIST_ELEMENTS_RO(bgp->vrf_export_rtl, node, l3rt))
			json_object_array_add(
				json_export_rts,
				json_object_new_string(
					ecommunity_str(l3rt->ecom)));
		json_object_object_add(json, "export-rts", json_export_rts);

		/* import rts */
		for (ALL_LIST_ELEMENTS_RO(bgp->vrf_import_rtl, node, l3rt))
			json_object_array_add(
				json_import_rts,
				json_object_new_string(
					ecommunity_str(l3rt->ecom)));
		json_object_object_add(json, "import-rts", json_import_rts);
		json_object_string_addf(json, "rd",
					BGP_RD_AS_FORMAT(bgp->asnotation),
					&bgp->vrf_prd);
	}

	if (uj)
		vty_json(vty, json);
	return CMD_SUCCESS;
}

static int add_rt(struct bgp *bgp, struct ecommunity *ecom, bool is_import,
		  bool is_wildcard)
{
	/* Do nothing if we already have this route-target */
	if (is_import) {
		if (!bgp_evpn_vrf_rt_matches_existing(bgp->vrf_import_rtl,
						      ecom))
			bgp_evpn_configure_import_rt_for_vrf(bgp, ecom,
							     is_wildcard);
		else
			return -1;
	} else {
		if (!bgp_evpn_vrf_rt_matches_existing(bgp->vrf_export_rtl,
						      ecom))
			bgp_evpn_configure_export_rt_for_vrf(bgp, ecom);
		else
			return -1;
	}

	return 0;
}

static int del_rt(struct bgp *bgp, struct ecommunity *ecom, bool is_import)
{
	/* Verify we already have this route-target */
	if (is_import) {
		if (!bgp_evpn_vrf_rt_matches_existing(bgp->vrf_import_rtl,
						      ecom))
			return -1;

		bgp_evpn_unconfigure_import_rt_for_vrf(bgp, ecom);
	} else {
		if (!bgp_evpn_vrf_rt_matches_existing(bgp->vrf_export_rtl,
						      ecom))
			return -1;

		bgp_evpn_unconfigure_export_rt_for_vrf(bgp, ecom);
	}

	return 0;
}

static int parse_rtlist(struct bgp *bgp, struct vty *vty, int argc,
			struct cmd_token **argv, int rt_idx, bool is_add,
			bool is_import)
{
	int ret = CMD_SUCCESS;
	bool is_wildcard = false;
	struct ecommunity *ecom = NULL;

	for (int i = rt_idx; i < argc; i++) {
		is_wildcard = false;

		/*
		 * Special handling for wildcard '*' here.
		 *
		 * Let's just convert it to 0 here so we dont have to modify
		 * the ecommunity parser.
		 */
		if ((argv[i]->arg)[0] == '*') {
			(argv[i]->arg)[0] = '0';
			is_wildcard = true;
		}

		ecom = ecommunity_str2com(argv[i]->arg, ECOMMUNITY_ROUTE_TARGET,
					  0);

		/* Put it back as was */
		if (is_wildcard)
			(argv[i]->arg)[0] = '*';

		if (!ecom) {
			vty_out(vty, "%% Malformed Route Target list\n");
			ret = CMD_WARNING;
			continue;
		}

		ecommunity_str(ecom);

		if (is_add) {
			if (add_rt(bgp, ecom, is_import, is_wildcard) != 0) {
				vty_out(vty,
					"%% RT specified already configured for this VRF: %s\n",
					argv[i]->arg);
				ecommunity_free(&ecom);
				ret = CMD_WARNING;
			}

		} else {
			if (del_rt(bgp, ecom, is_import) != 0) {
				vty_out(vty,
					"%% RT specified does not match configuration for this VRF: %s\n",
					argv[i]->arg);
				ret = CMD_WARNING;
			}

			ecommunity_free(&ecom);
		}
	}

	return ret;
}

/* import/export rt for l3vni-vrf */
DEFUN (bgp_evpn_vrf_rt,
       bgp_evpn_vrf_rt_cmd,
       "route-target <both|import|export> RTLIST...",
       "Route Target\n"
       "import and export\n"
       "import\n"
       "export\n"
       "Space separated route target list (A.B.C.D:MN|EF:OPQR|GHJK:MN|*:OPQR|*:MN)\n")
{
	int ret = CMD_SUCCESS;
	int tmp_ret = CMD_SUCCESS;
	int rt_type;
	struct bgp *bgp = VTY_GET_CONTEXT(bgp);

	if (!bgp)
		return CMD_WARNING_CONFIG_FAILED;

	if (!strcmp(argv[1]->arg, "import"))
		rt_type = RT_TYPE_IMPORT;
	else if (!strcmp(argv[1]->arg, "export"))
		rt_type = RT_TYPE_EXPORT;
	else if (!strcmp(argv[1]->arg, "both"))
		rt_type = RT_TYPE_BOTH;
	else {
		vty_out(vty, "%% Invalid Route Target type\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (strmatch(argv[2]->arg, "auto")) {
		vty_out(vty, "%% `auto` cannot be configured via list\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (rt_type != RT_TYPE_IMPORT) {
		for (int i = 2; i < argc; i++) {
			if ((argv[i]->arg)[0] == '*') {
				vty_out(vty,
					"%% Wildcard '*' only applicable for import\n");
				return CMD_WARNING_CONFIG_FAILED;
			}
		}
	}

	/* Add/update the import route-target */
	if (rt_type == RT_TYPE_BOTH || rt_type == RT_TYPE_IMPORT)
		tmp_ret = parse_rtlist(bgp, vty, argc, argv, 2, true, true);

	if (ret == CMD_SUCCESS && tmp_ret != CMD_SUCCESS)
		ret = tmp_ret;

	if (rt_type == RT_TYPE_BOTH || rt_type == RT_TYPE_EXPORT)
		tmp_ret = parse_rtlist(bgp, vty, argc, argv, 2, true, false);

	if (ret == CMD_SUCCESS && tmp_ret != CMD_SUCCESS)
		ret = tmp_ret;

	return ret;
}

DEFPY (bgp_evpn_vrf_rt_auto,
       bgp_evpn_vrf_rt_auto_cmd,
       "route-target <both|import|export>$type auto",
       "Route Target\n"
       "import and export\n"
       "import\n"
       "export\n"
       "Automatically derive route target\n")
{
	struct bgp *bgp = VTY_GET_CONTEXT(bgp);
	int rt_type;

	if (!bgp)
		return CMD_WARNING_CONFIG_FAILED;

	if (strmatch(type, "import"))
		rt_type = RT_TYPE_IMPORT;
	else if (strmatch(type, "export"))
		rt_type = RT_TYPE_EXPORT;
	else if (strmatch(type, "both"))
		rt_type = RT_TYPE_BOTH;
	else {
		vty_out(vty, "%% Invalid Route Target type\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (rt_type == RT_TYPE_BOTH || rt_type == RT_TYPE_IMPORT)
		bgp_evpn_configure_import_auto_rt_for_vrf(bgp);

	if (rt_type == RT_TYPE_BOTH || rt_type == RT_TYPE_EXPORT)
		bgp_evpn_configure_export_auto_rt_for_vrf(bgp);

	return CMD_SUCCESS;
}

DEFUN (no_bgp_evpn_vrf_rt,
       no_bgp_evpn_vrf_rt_cmd,
       "no route-target <both|import|export> RTLIST...",
       NO_STR
       "Route Target\n"
       "import and export\n"
       "import\n"
       "export\n"
       "Space separated route target list (A.B.C.D:MN|EF:OPQR|GHJK:MN)\n")
{
	struct bgp *bgp = VTY_GET_CONTEXT(bgp);
	int ret = CMD_SUCCESS;
	int tmp_ret = CMD_SUCCESS;
	int rt_type;

	if (!bgp)
		return CMD_WARNING_CONFIG_FAILED;

	if (!strcmp(argv[2]->arg, "import"))
		rt_type = RT_TYPE_IMPORT;
	else if (!strcmp(argv[2]->arg, "export"))
		rt_type = RT_TYPE_EXPORT;
	else if (!strcmp(argv[2]->arg, "both"))
		rt_type = RT_TYPE_BOTH;
	else {
		vty_out(vty, "%% Invalid Route Target type\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (!strcmp(argv[3]->arg, "auto")) {
		vty_out(vty, "%% `auto` cannot be unconfigured via list\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (rt_type == RT_TYPE_IMPORT) {
		if (!CHECK_FLAG(bgp->vrf_flags, BGP_VRF_IMPORT_RT_CFGD)) {
			vty_out(vty,
				"%% Import RT is not configured for this VRF\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	} else if (rt_type == RT_TYPE_EXPORT) {
		if (!CHECK_FLAG(bgp->vrf_flags, BGP_VRF_EXPORT_RT_CFGD)) {
			vty_out(vty,
				"%% Export RT is not configured for this VRF\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	} else if (rt_type == RT_TYPE_BOTH) {
		if (!CHECK_FLAG(bgp->vrf_flags, BGP_VRF_IMPORT_RT_CFGD)
		    && !CHECK_FLAG(bgp->vrf_flags, BGP_VRF_EXPORT_RT_CFGD)) {
			vty_out(vty,
				"%% Import/Export RT is not configured for this VRF\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	if (rt_type != RT_TYPE_IMPORT) {
		for (int i = 3; i < argc; i++) {
			if ((argv[i]->arg)[0] == '*') {
				vty_out(vty,
					"%% Wildcard '*' only applicable for import\n");
				return CMD_WARNING_CONFIG_FAILED;
			}
		}
	}

	if (rt_type == RT_TYPE_BOTH || rt_type == RT_TYPE_IMPORT)
		tmp_ret = parse_rtlist(bgp, vty, argc, argv, 3, false, true);

	if (ret == CMD_SUCCESS && tmp_ret != CMD_SUCCESS)
		ret = tmp_ret;

	if (rt_type == RT_TYPE_BOTH || rt_type == RT_TYPE_EXPORT)
		tmp_ret = parse_rtlist(bgp, vty, argc, argv, 3, false, false);

	if (ret == CMD_SUCCESS && tmp_ret != CMD_SUCCESS)
		ret = tmp_ret;

	return ret;
}

DEFPY (no_bgp_evpn_vrf_rt_auto,
       no_bgp_evpn_vrf_rt_auto_cmd,
       "no route-target <both|import|export>$type auto",
       NO_STR
       "Route Target\n"
       "import and export\n"
       "import\n"
       "export\n"
       "Automatically derive route target\n")
{
	struct bgp *bgp = VTY_GET_CONTEXT(bgp);
	int rt_type;

	if (!bgp)
		return CMD_WARNING_CONFIG_FAILED;

	if (strmatch(type, "import"))
		rt_type = RT_TYPE_IMPORT;
	else if (strmatch(type, "export"))
		rt_type = RT_TYPE_EXPORT;
	else if (strmatch(type, "both"))
		rt_type = RT_TYPE_BOTH;
	else {
		vty_out(vty, "%% Invalid Route Target type\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (rt_type == RT_TYPE_IMPORT) {
		if (!CHECK_FLAG(bgp->vrf_flags, BGP_VRF_IMPORT_AUTO_RT_CFGD)) {
			vty_out(vty,
				"%% Import AUTO RT is not configured for this VRF\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	} else if (rt_type == RT_TYPE_EXPORT) {
		if (!CHECK_FLAG(bgp->vrf_flags, BGP_VRF_EXPORT_AUTO_RT_CFGD)) {
			vty_out(vty,
				"%% Export AUTO RT is not configured for this VRF\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	} else if (rt_type == RT_TYPE_BOTH) {
		if (!CHECK_FLAG(bgp->vrf_flags, BGP_VRF_IMPORT_AUTO_RT_CFGD) &&
		    !CHECK_FLAG(bgp->vrf_flags, BGP_VRF_EXPORT_AUTO_RT_CFGD)) {
			vty_out(vty,
				"%% Import/Export AUTO RT is not configured for this VRF\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	if (rt_type == RT_TYPE_BOTH || rt_type == RT_TYPE_IMPORT)
		bgp_evpn_unconfigure_import_auto_rt_for_vrf(bgp);

	if (rt_type == RT_TYPE_BOTH || rt_type == RT_TYPE_EXPORT)
		bgp_evpn_unconfigure_export_auto_rt_for_vrf(bgp);

	return CMD_SUCCESS;
}

DEFPY(bgp_evpn_ead_ess_frag_evi_limit, bgp_evpn_ead_es_frag_evi_limit_cmd,
      "[no$no] ead-es-frag evi-limit (1-1000)$limit",
      NO_STR
      "EAD ES fragment config\n"
      "EVIs per-fragment\n"
      "limit\n")
{
	bgp_mh_info->evi_per_es_frag =
		no ? BGP_EVPN_MAX_EVI_PER_ES_FRAG : limit;

	return CMD_SUCCESS;
}

DEFUN(bgp_evpn_ead_es_rt, bgp_evpn_ead_es_rt_cmd,
      "ead-es-route-target export RT",
      "EAD ES Route Target\n"
      "export\n"
      "Route target (A.B.C.D:MN|EF:OPQR|GHJK:MN)\n")
{
	struct bgp *bgp = VTY_GET_CONTEXT(bgp);
	struct ecommunity *ecomadd = NULL;

	if (!bgp)
		return CMD_WARNING;

	if (!EVPN_ENABLED(bgp)) {
		vty_out(vty, "This command is only supported under EVPN VRF\n");
		return CMD_WARNING;
	}

	/* Add/update the export route-target */
	ecomadd = ecommunity_str2com(argv[2]->arg, ECOMMUNITY_ROUTE_TARGET, 0);
	if (!ecomadd) {
		vty_out(vty, "%% Malformed Route Target list\n");
		return CMD_WARNING;
	}
	ecommunity_str(ecomadd);

	/* Do nothing if we already have this export route-target */
	if (!bgp_evpn_rt_matches_existing(bgp_mh_info->ead_es_export_rtl,
					  ecomadd))
		bgp_evpn_mh_config_ead_export_rt(bgp, ecomadd, false);
	else
		ecommunity_free(&ecomadd);

	return CMD_SUCCESS;
}

DEFUN(no_bgp_evpn_ead_es_rt, no_bgp_evpn_ead_es_rt_cmd,
      "no ead-es-route-target export RT",
      NO_STR
      "EAD ES Route Target\n"
      "export\n" EVPN_ASN_IP_HELP_STR)
{
	struct bgp *bgp = VTY_GET_CONTEXT(bgp);
	struct ecommunity *ecomdel = NULL;

	if (!bgp)
		return CMD_WARNING;

	if (!EVPN_ENABLED(bgp)) {
		vty_out(vty, "This command is only supported under EVPN VRF\n");
		return CMD_WARNING;
	}

	ecomdel = ecommunity_str2com(argv[3]->arg, ECOMMUNITY_ROUTE_TARGET, 0);
	if (!ecomdel) {
		vty_out(vty, "%% Malformed Route Target list\n");
		return CMD_WARNING;
	}
	ecommunity_str(ecomdel);

	if (!bgp_evpn_rt_matches_existing(bgp_mh_info->ead_es_export_rtl,
					  ecomdel)) {
		ecommunity_free(&ecomdel);
		vty_out(vty,
			"%% RT specified does not match EAD-ES RT configuration\n");
		return CMD_WARNING;
	}
	bgp_evpn_mh_config_ead_export_rt(bgp, ecomdel, true);

	ecommunity_free(&ecomdel);
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
		/* Note that first of the two RTs is created for "both" type */
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
		else
			ecommunity_free(&ecomadd);
	}

	/* Add/update the export route-target */
	if (rt_type == RT_TYPE_BOTH || rt_type == RT_TYPE_EXPORT) {
		/* Note that second of the two RTs is created for "both" type */
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
		else
			ecommunity_free(&ecomadd);
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
       EVPN_ASN_IP_HELP_STR)
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
			ecommunity_free(&ecomdel);
			vty_out(vty,
				"%% RT specified does not match configuration for this VNI\n");
			return CMD_WARNING;
		}
		evpn_unconfigure_import_rt(bgp, vpn, ecomdel);
	} else if (rt_type == RT_TYPE_EXPORT) {
		if (!bgp_evpn_rt_matches_existing(vpn->export_rtl, ecomdel)) {
			ecommunity_free(&ecomdel);
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
			ecommunity_free(&ecomdel);
			vty_out(vty,
				"%% RT specified does not match configuration for this VNI\n");
			return CMD_WARNING;
		}
	}

	ecommunity_free(&ecomdel);
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
	if (bgp->advertise_all_vni)
		vty_out(vty, "  advertise-all-vni\n");

	if (hashcount(bgp->vnihash)) {
		struct list *vnilist = hash_to_list(bgp->vnihash);
		struct listnode *ln;
		struct bgpevpn *data;

		list_sort(vnilist, vni_cmp);
		for (ALL_LIST_ELEMENTS_RO(vnilist, ln, data))
			write_vni_config(vty, data);

		list_delete(&vnilist);
	}

	if (bgp->advertise_autort_rfc8365)
		vty_out(vty, "  autort rfc8365-compatible\n");

	if (bgp->advertise_gw_macip)
		vty_out(vty, "  advertise-default-gw\n");

	if (bgp->evpn_info->advertise_svi_macip)
		vty_out(vty, "  advertise-svi-ip\n");

	if (bgp->evpn_info->soo) {
		char *ecom_str;

		ecom_str = ecommunity_ecom2str(bgp->evpn_info->soo,
					       ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
		vty_out(vty, "  mac-vrf soo %s\n", ecom_str);
		ecommunity_strfree(&ecom_str);
	}

	if (bgp->resolve_overlay_index)
		vty_out(vty, "  enable-resolve-overlay-index\n");

	if (bgp_mh_info->evi_per_es_frag != BGP_EVPN_MAX_EVI_PER_ES_FRAG)
		vty_out(vty, "  ead-es-frag evi-limit %u\n",
			bgp_mh_info->evi_per_es_frag);

	if (bgp_mh_info->host_routes_use_l3nhg !=
			BGP_EVPN_MH_USE_ES_L3NHG_DEF) {
		if (bgp_mh_info->host_routes_use_l3nhg)
			vty_out(vty, "  use-es-l3nhg\n");
		else
			vty_out(vty, "  no use-es-l3nhg\n");
	}

	if (bgp_mh_info->ead_evi_rx != BGP_EVPN_MH_EAD_EVI_RX_DEF) {
		if (bgp_mh_info->ead_evi_rx)
			vty_out(vty, "  no disable-ead-evi-rx\n");
		else
			vty_out(vty, "  disable-ead-evi-rx\n");
	}

	if (bgp_mh_info->ead_evi_tx != BGP_EVPN_MH_EAD_EVI_TX_DEF) {
		if (bgp_mh_info->ead_evi_tx)
			vty_out(vty, "  no disable-ead-evi-tx\n");
		else
			vty_out(vty, "  disable-ead-evi-tx\n");
	}

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
		       BGP_L2VPN_EVPN_ADV_IPV4_UNICAST)) {
		if (bgp->adv_cmd_rmap[AFI_IP][SAFI_UNICAST].name)
			vty_out(vty, "  advertise ipv4 unicast route-map %s\n",
				bgp->adv_cmd_rmap[AFI_IP][SAFI_UNICAST].name);
		else
			vty_out(vty,
				"  advertise ipv4 unicast\n");
	} else if (CHECK_FLAG(bgp->af_flags[AFI_L2VPN][SAFI_EVPN],
		   BGP_L2VPN_EVPN_ADV_IPV4_UNICAST_GW_IP)) {
		if (bgp->adv_cmd_rmap[AFI_IP][SAFI_UNICAST].name)
			vty_out(vty,
				"  advertise ipv4 unicast gateway-ip route-map %s\n",
				bgp->adv_cmd_rmap[AFI_IP][SAFI_UNICAST].name);
		else
			vty_out(vty, "  advertise ipv4 unicast gateway-ip\n");
	}

	/* EAD ES export route-target */
	if (listcount(bgp_mh_info->ead_es_export_rtl)) {
		struct ecommunity *ecom;
		char *ecom_str;
		struct listnode *node;

		for (ALL_LIST_ELEMENTS_RO(bgp_mh_info->ead_es_export_rtl, node,
					  ecom)) {

			ecom_str = ecommunity_ecom2str(
				ecom, ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
			vty_out(vty, "  ead-es-route-target export %s\n",
				ecom_str);
			XFREE(MTYPE_ECOMMUNITY_STR, ecom_str);
		}
	}

	if (CHECK_FLAG(bgp->af_flags[AFI_L2VPN][SAFI_EVPN],
		       BGP_L2VPN_EVPN_ADV_IPV6_UNICAST)) {
		if (bgp->adv_cmd_rmap[AFI_IP6][SAFI_UNICAST].name)
			vty_out(vty,
				"  advertise ipv6 unicast route-map %s\n",
				bgp->adv_cmd_rmap[AFI_IP6][SAFI_UNICAST].name);
		else
			vty_out(vty,
				"  advertise ipv6 unicast\n");
	} else if (CHECK_FLAG(bgp->af_flags[AFI_L2VPN][SAFI_EVPN],
			      BGP_L2VPN_EVPN_ADV_IPV6_UNICAST_GW_IP)) {
		if (bgp->adv_cmd_rmap[AFI_IP6][SAFI_UNICAST].name)
			vty_out(vty,
				"  advertise ipv6 unicast gateway-ip route-map %s\n",
				bgp->adv_cmd_rmap[AFI_IP6][SAFI_UNICAST].name);
		else
			vty_out(vty, "  advertise ipv6 unicast gateway-ip\n");
	}

	if (CHECK_FLAG(bgp->af_flags[AFI_L2VPN][SAFI_EVPN],
		       BGP_L2VPN_EVPN_DEFAULT_ORIGINATE_IPV4))
		vty_out(vty, "  default-originate ipv4\n");

	if (CHECK_FLAG(bgp->af_flags[AFI_L2VPN][SAFI_EVPN],
		       BGP_L2VPN_EVPN_DEFAULT_ORIGINATE_IPV6))
		vty_out(vty, "  default-originate ipv6\n");

	if (bgp->inst_type == BGP_INSTANCE_TYPE_VRF) {
		if (!bgp->evpn_info->advertise_pip)
			vty_out(vty, "  no advertise-pip\n");
		if (bgp->evpn_info->advertise_pip) {
			if (bgp->evpn_info->pip_ip_static.s_addr
			    != INADDR_ANY) {
				vty_out(vty, "  advertise-pip ip %pI4",
					&bgp->evpn_info->pip_ip_static);
				if (!is_zero_mac(&(
					    bgp->evpn_info->pip_rmac_static))) {
					char buf[ETHER_ADDR_STRLEN];

					vty_out(vty, " mac %s",
						prefix_mac2str(
							&bgp->evpn_info
								 ->pip_rmac,
							buf, sizeof(buf)));
				}
				vty_out(vty, "\n");
			}
		}
	}
	if (CHECK_FLAG(bgp->vrf_flags, BGP_VRF_RD_CFGD))
		vty_out(vty, "  rd %s\n", bgp->vrf_prd_pretty);

	/* import route-target */
	if (CHECK_FLAG(bgp->vrf_flags, BGP_VRF_IMPORT_RT_CFGD)) {
		char *ecom_str;
		struct listnode *node, *nnode;
		struct vrf_route_target *l3rt;

		for (ALL_LIST_ELEMENTS(bgp->vrf_import_rtl, node, nnode,
				       l3rt)) {

			if (CHECK_FLAG(l3rt->flags, BGP_VRF_RT_AUTO))
				continue;

			ecom_str = ecommunity_ecom2str(
				l3rt->ecom, ECOMMUNITY_FORMAT_ROUTE_MAP, 0);

			if (CHECK_FLAG(l3rt->flags, BGP_VRF_RT_WILD)) {
				char *vni_str = NULL;

				vni_str = strchr(ecom_str, ':');
				if (!vni_str) {
					XFREE(MTYPE_ECOMMUNITY_STR, ecom_str);
					continue;
				}

				/* Move pointer to vni */
				vni_str += 1;

				vty_out(vty, "  route-target import *:%s\n",
					vni_str);

			} else
				vty_out(vty, "  route-target import %s\n",
					ecom_str);

			XFREE(MTYPE_ECOMMUNITY_STR, ecom_str);
		}
	}

	/* import route-target auto */
	if (CHECK_FLAG(bgp->vrf_flags, BGP_VRF_IMPORT_AUTO_RT_CFGD))
		vty_out(vty, "  route-target import auto\n");

	/* export route-target */
	if (CHECK_FLAG(bgp->vrf_flags, BGP_VRF_EXPORT_RT_CFGD)) {
		char *ecom_str;
		struct listnode *node, *nnode;
		struct vrf_route_target *l3rt;

		for (ALL_LIST_ELEMENTS(bgp->vrf_export_rtl, node, nnode,
				       l3rt)) {

			if (CHECK_FLAG(l3rt->flags, BGP_VRF_RT_AUTO))
				continue;

			ecom_str = ecommunity_ecom2str(
				l3rt->ecom, ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
			vty_out(vty, "  route-target export %s\n", ecom_str);
			XFREE(MTYPE_ECOMMUNITY_STR, ecom_str);
		}
	}

	/* export route-target auto */
	if (CHECK_FLAG(bgp->vrf_flags, BGP_VRF_EXPORT_AUTO_RT_CFGD))
		vty_out(vty, "  route-target export auto\n");
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
	install_element(BGP_EVPN_NODE, &macvrf_soo_global_cmd);
	install_element(BGP_EVPN_NODE, &no_macvrf_soo_global_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_advertise_type5_cmd);
	install_element(BGP_EVPN_NODE, &no_bgp_evpn_advertise_type5_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_default_originate_cmd);
	install_element(BGP_EVPN_NODE, &no_bgp_evpn_default_originate_cmd);
	install_element(BGP_EVPN_NODE, &dup_addr_detection_cmd);
	install_element(BGP_EVPN_NODE, &dup_addr_detection_auto_recovery_cmd);
	install_element(BGP_EVPN_NODE, &no_dup_addr_detection_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_flood_control_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_advertise_pip_ip_mac_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_use_es_l3nhg_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_ead_evi_rx_disable_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_ead_evi_tx_disable_cmd);
	install_element(BGP_EVPN_NODE,
			&bgp_evpn_enable_resolve_overlay_index_cmd);

	/* test commands */
	install_element(BGP_EVPN_NODE, &test_es_add_cmd);
	install_element(BGP_EVPN_NODE, &test_es_vni_add_cmd);

	/* "show bgp l2vpn evpn" commands. */
	install_element(VIEW_NODE, &show_bgp_l2vpn_evpn_es_cmd);
	install_element(VIEW_NODE, &show_bgp_l2vpn_evpn_es_evi_cmd);
	install_element(VIEW_NODE, &show_bgp_l2vpn_evpn_es_vrf_cmd);
	install_element(VIEW_NODE, &show_bgp_l2vpn_evpn_nh_cmd);
	install_element(VIEW_NODE, &show_bgp_l2vpn_evpn_vni_cmd);
	install_element(VIEW_NODE, &show_bgp_l2vpn_evpn_vni_remote_ip_hash_cmd);
	install_element(VIEW_NODE, &show_bgp_l2vpn_evpn_vni_svi_hash_cmd);
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
	install_element(VIEW_NODE,
			&show_bgp_l2vpn_evpn_route_mac_ip_evi_es_cmd);
	install_element(VIEW_NODE,
			&show_bgp_l2vpn_evpn_route_mac_ip_global_es_cmd);
	install_element(VIEW_NODE, &show_bgp_l2vpn_evpn_import_rt_cmd);
	install_element(VIEW_NODE, &show_bgp_l2vpn_evpn_vrf_import_rt_cmd);

	/* "show bgp vni" commands. */
	install_element(VIEW_NODE, &show_bgp_vni_all_cmd);
	install_element(VIEW_NODE, &show_bgp_vni_all_ead_cmd);
	install_element(VIEW_NODE, &show_bgp_vni_all_macip_mac_cmd);
	install_element(VIEW_NODE, &show_bgp_vni_all_macip_ip_cmd);
	install_element(VIEW_NODE, &show_bgp_vni_all_imet_cmd);
	install_element(VIEW_NODE, &show_bgp_vni_cmd);
	install_element(VIEW_NODE, &show_bgp_vni_ead_cmd);
	install_element(VIEW_NODE, &show_bgp_vni_macip_mac_cmd);
	install_element(VIEW_NODE, &show_bgp_vni_macip_ip_cmd);
	install_element(VIEW_NODE, &show_bgp_vni_imet_cmd);
	install_element(VIEW_NODE, &show_bgp_vni_macip_mac_addr_cmd);
	install_element(VIEW_NODE, &show_bgp_vni_macip_ip_addr_cmd);

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
	install_element(BGP_EVPN_NODE, &bgp_evpn_vrf_rt_auto_cmd);
	install_element(BGP_EVPN_NODE, &no_bgp_evpn_vrf_rt_auto_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_ead_es_rt_cmd);
	install_element(BGP_EVPN_NODE, &no_bgp_evpn_ead_es_rt_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_ead_es_frag_evi_limit_cmd);
	install_element(BGP_EVPN_VNI_NODE, &bgp_evpn_advertise_svi_ip_vni_cmd);
	install_element(BGP_EVPN_VNI_NODE,
			&bgp_evpn_advertise_default_gw_vni_cmd);
	install_element(BGP_EVPN_VNI_NODE,
			&no_bgp_evpn_advertise_default_gw_vni_cmd);
	install_element(BGP_EVPN_VNI_NODE, &bgp_evpn_advertise_vni_subnet_cmd);
	install_element(BGP_EVPN_VNI_NODE,
			&no_bgp_evpn_advertise_vni_subnet_cmd);
}
