// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra EVPN for VxLAN code
 * Copyright (C) 2016, 2017 Cumulus Networks, Inc.
 */
#include <zebra.h>

#include "hash.h"
#include "if.h"
#include "jhash.h"
#include "linklist.h"
#include "log.h"
#include "memory.h"
#include "prefix.h"
#include "stream.h"
#include "table.h"
#include "vlan.h"
#include "vxlan.h"
#ifdef GNU_LINUX
#include <linux/neighbour.h>
#endif

#include "zebra/zebra_router.h"
#include "zebra/debug.h"
#include "zebra/interface.h"
#include "zebra/rib.h"
#include "zebra/rt.h"
#include "zebra/rt_netlink.h"
#include "zebra/zebra_errors.h"
#include "zebra/zebra_l2.h"
#include "zebra/zebra_l2_bridge_if.h"
#include "zebra/zebra_ns.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_vxlan.h"
#include "zebra/zebra_vxlan_private.h"
#include "zebra/zebra_evpn.h"
#include "zebra/zebra_evpn_mac.h"
#include "zebra/zebra_evpn_neigh.h"
#include "zebra/zebra_evpn_mh.h"
#include "zebra/zebra_evpn_vxlan.h"
#include "zebra/zebra_router.h"

DEFINE_MTYPE_STATIC(ZEBRA, ZEVPN, "VNI hash");
DEFINE_MTYPE_STATIC(ZEBRA, ZEVPN_VTEP, "VNI remote VTEP");

/* PMSI strings. */
#define VXLAN_FLOOD_STR_NO_INFO "-"
#define VXLAN_FLOOD_STR_DEFAULT VXLAN_FLOOD_STR_NO_INFO
static const struct message zvtep_flood_str[] = {
	{VXLAN_FLOOD_DISABLED, VXLAN_FLOOD_STR_NO_INFO},
	{VXLAN_FLOOD_PIM_SM, "PIM-SM"},
	{VXLAN_FLOOD_HEAD_END_REPL, "HER"},
	{0}
};

int advertise_gw_macip_enabled(struct zebra_evpn *zevpn)
{
	struct zebra_vrf *zvrf;

	zvrf = zebra_vrf_get_evpn();
	if (zvrf->advertise_gw_macip)
		return 1;

	if (zevpn && zevpn->advertise_gw_macip)
		return 1;

	return 0;
}

int advertise_svi_macip_enabled(struct zebra_evpn *zevpn)
{
	struct zebra_vrf *zvrf;

	zvrf = zebra_vrf_get_evpn();
	if (zvrf->advertise_svi_macip)
		return 1;

	if (zevpn && zevpn->advertise_svi_macip)
		return 1;

	return 0;
}

/*
 * Print a specific EVPN entry.
 */
void zebra_evpn_print(struct zebra_evpn *zevpn, void **ctxt)
{

	struct vty *vty = NULL;
	struct zebra_vtep *zvtep = NULL;
	uint32_t num_macs = 0;
	uint32_t num_neigh = 0;
	uint32_t num_vteps = 0;
	json_object *json = NULL;
	json_object *json_vtep_list = NULL;
	json_object *json_vtep = NULL;

	vty = ctxt[0];
	json = ctxt[1];

	if (json == NULL) {
		vty_out(vty, "VNI: %u\n", zevpn->vni);
		vty_out(vty, " Type: %s\n", "L2");
		vty_out(vty, " Vlan: %u\n", zevpn->vid);
		vty_out(vty, " Bridge: %s\n",
			zevpn->bridge_if ? zevpn->bridge_if->name : "-");
		vty_out(vty, " Tenant VRF: %s\n", vrf_id_to_name(zevpn->vrf_id));
	} else {
		json_object_int_add(json, "vni", zevpn->vni);
		json_object_string_add(json, "type", "L2");
		json_object_string_add(json, "tenantVrf", vrf_id_to_name(zevpn->vrf_id));
	}

	if (!zevpn->vxlan_if) { // unexpected
		if (json == NULL)
			vty_out(vty, " VxLAN interface: unknown\n");
		else
			json_object_string_add(json, "vxlanInterface", "unknown");
		return;
	}
	num_macs = num_valid_macs(zevpn);
	num_neigh = hashcount(zevpn->neigh_table);
	if (json == NULL) {
		vty_out(vty, " VxLAN interface: %s\n", zevpn->vxlan_if->name);
		vty_out(vty, " VxLAN ifIndex: %u\n", zevpn->vxlan_if->ifindex);
		vty_out(vty, " SVI interface: %s\n",
			(zevpn->svi_if ? zevpn->svi_if->name : ""));
		vty_out(vty, " SVI ifIndex: %u\n",
			(zevpn->svi_if ? zevpn->svi_if->ifindex : 0));
		vty_out(vty, " Local VTEP IP: %pI4\n", &zevpn->local_vtep_ip);
		vty_out(vty, " Mcast group: %pI4\n", &zevpn->mcast_grp);
	} else {
		json_object_string_add(json, "vxlanInterface", zevpn->vxlan_if->name);
		json_object_int_add(json, "vxlanIfindex", zevpn->vxlan_if->ifindex);
		if (zevpn->svi_if) {
			json_object_string_add(json, "sviInterface", zevpn->svi_if->name);
			json_object_int_add(json, "sviIfindex", zevpn->svi_if->ifindex);
		}
		json_object_string_addf(json, "vtepIp", "%pI4", &zevpn->local_vtep_ip);
		json_object_string_addf(json, "mcastGroup", "%pI4", &zevpn->mcast_grp);
		json_object_string_add(json, "advertiseGatewayMacip",
				       zevpn->advertise_gw_macip ? "Yes" : "No");
		json_object_string_add(json, "advertiseSviMacip",
				       zevpn->advertise_svi_macip ? "Yes" : "No");
		json_object_int_add(json, "numMacs", num_macs);
		json_object_int_add(json, "numArpNd", num_neigh);
	}
	if (!zevpn->vteps) {
		if (json == NULL)
			vty_out(vty, " No remote VTEPs known for this VNI\n");
		else
			json_object_int_add(json, "numRemoteVteps", num_vteps);
	} else {
		if (json == NULL)
			vty_out(vty, " Remote VTEPs for this VNI:\n");
		else
			json_vtep_list = json_object_new_array();
		for (zvtep = zevpn->vteps; zvtep; zvtep = zvtep->next) {
			const char *flood_str = lookup_msg(
				zvtep_flood_str, zvtep->flood_control, VXLAN_FLOOD_STR_DEFAULT);

			if (json == NULL) {
				vty_out(vty, "  %pI4 flood: %s\n", &zvtep->vtep_ip, flood_str);
			} else {
				json_vtep = json_object_new_object();
				json_object_string_addf(json_vtep, "ip", "%pI4", &zvtep->vtep_ip);
				json_object_string_add(json_vtep, "flood", flood_str);
				json_object_array_add(json_vtep_list, json_vtep);
			}
			num_vteps++;
		}
		if (json) {
			json_object_int_add(json, "numRemoteVteps", num_vteps);
			json_object_object_add(json, "remoteVteps", json_vtep_list);
		}
	}
	if (json == NULL) {
		vty_out(vty,
			" Number of MACs (local and remote) known for this VNI: %u\n",
			num_macs);
		vty_out(vty,
			" Number of ARPs (IPv4 and IPv6, local and remote) "
			"known for this VNI: %u\n",
			num_neigh);
		vty_out(vty, " Advertise-gw-macip: %s\n",
			zevpn->advertise_gw_macip ? "Yes" : "No");
		vty_out(vty, " Advertise-svi-macip: %s\n",
			zevpn->advertise_svi_macip ? "Yes" : "No");
	}
}

/*
 * Print an EVPN hash entry - called for display of all VNIs.
 */
void zebra_evpn_print_hash(struct hash_bucket *bucket, void *ctxt[])
{
	struct vty *vty;
	struct zebra_evpn *zevpn;
	struct zebra_vtep *zvtep;
	uint32_t num_vteps = 0;
	uint32_t num_macs = 0;
	uint32_t num_neigh = 0;
	json_object *json = NULL;
	json_object *json_evpn = NULL;
	json_object *json_ip_str = NULL;
	json_object *json_vtep_list = NULL;
	char buf[PREFIX_STRLEN];

	vty = ctxt[0];
	json = ctxt[1];

	zevpn = (struct zebra_evpn *)bucket->data;

	zvtep = zevpn->vteps;
	while (zvtep) {
		num_vteps++;
		zvtep = zvtep->next;
	}

	num_macs = num_valid_macs(zevpn);
	num_neigh = hashcount(zevpn->neigh_table);
	if (json == NULL)
		vty_out(vty, "%-10u %-4s %-21s %-8u %-8u %-15u %-37s\n",
			zevpn->vni, "L2",
			zevpn->vxlan_if ? zevpn->vxlan_if->name : "unknown",
			num_macs, num_neigh, num_vteps,
			vrf_id_to_name(zevpn->vrf_id));
	else {
		char vni_str[VNI_STR_LEN];
		snprintf(vni_str, VNI_STR_LEN, "%u", zevpn->vni);
		json_evpn = json_object_new_object();
		json_object_int_add(json_evpn, "vni", zevpn->vni);
		json_object_string_add(json_evpn, "type", "L2");
		json_object_string_add(json_evpn, "vxlanIf",
				       zevpn->vxlan_if ? zevpn->vxlan_if->name : "unknown");
		json_object_int_add(json_evpn, "numMacs", num_macs);
		json_object_int_add(json_evpn, "numArpNd", num_neigh);
		json_object_int_add(json_evpn, "numRemoteVteps", num_vteps);
		json_object_string_add(json_evpn, "tenantVrf",
				       vrf_id_to_name(zevpn->vrf_id));
		if (num_vteps) {
			json_vtep_list = json_object_new_array();
			for (zvtep = zevpn->vteps; zvtep; zvtep = zvtep->next) {
				json_ip_str = json_object_new_string(
					inet_ntop(AF_INET, &zvtep->vtep_ip, buf, sizeof(buf)));
				json_object_array_add(json_vtep_list, json_ip_str);
			}
			json_object_object_add(json_evpn, "remoteVteps", json_vtep_list);
		}
		json_object_object_add(json, vni_str, json_evpn);
	}
}

/*
 * Print an EVPN hash entry in detail - called for display of all EVPNs.
 */
void zebra_evpn_print_hash_detail(struct hash_bucket *bucket, void *data)
{
	struct vty *vty;
	struct zebra_evpn *zevpn;
	json_object *json_array = NULL;
	bool use_json = false;
	struct zebra_evpn_show *zes = data;

	vty = zes->vty;
	json_array = zes->json;
	use_json = zes->use_json;

	zevpn = (struct zebra_evpn *)bucket->data;

	zebra_vxlan_print_vni(vty, zes->zvrf, zevpn->vni, use_json, json_array);

	if (!use_json)
		vty_out(vty, "\n");
}

int zebra_evpn_del_macip_for_intf(struct interface *ifp,
				  struct zebra_evpn *zevpn)
{
	struct connected *c = NULL;
	struct ethaddr macaddr;

	memcpy(&macaddr.octet, ifp->hw_addr, ETH_ALEN);

	frr_each_safe (if_connected, ifp->connected, c) {
		struct ipaddr ip;

		memset(&ip, 0, sizeof(struct ipaddr));
		if (!CHECK_FLAG(c->conf, ZEBRA_IFC_REAL))
			continue;

		if (c->address->family == AF_INET) {
			ip.ipa_type = IPADDR_V4;
			memcpy(&(ip.ipaddr_v4), &(c->address->u.prefix4),
			       sizeof(struct in_addr));
		} else if (c->address->family == AF_INET6) {
			ip.ipa_type = IPADDR_V6;
			memcpy(&(ip.ipaddr_v6), &(c->address->u.prefix6),
			       sizeof(struct in6_addr));
		} else {
			continue;
		}

		zebra_evpn_gw_macip_del(ifp, zevpn, &ip);
	}

	return 0;
}

int zebra_evpn_add_macip_for_intf(struct interface *ifp,
				  struct zebra_evpn *zevpn)
{
	struct connected *c = NULL;
	struct ethaddr macaddr;

	memcpy(&macaddr.octet, ifp->hw_addr, ETH_ALEN);

	frr_each_safe (if_connected, ifp->connected, c) {
		struct ipaddr ip;

		if (!CHECK_FLAG(c->conf, ZEBRA_IFC_REAL))
			continue;

		memset(&ip, 0, sizeof(struct ipaddr));
		if (c->address->family == AF_INET) {
			ip.ipa_type = IPADDR_V4;
			memcpy(&(ip.ipaddr_v4), &(c->address->u.prefix4),
			       sizeof(struct in_addr));
		} else if (c->address->family == AF_INET6) {
			ip.ipa_type = IPADDR_V6;
			memcpy(&(ip.ipaddr_v6), &(c->address->u.prefix6),
			       sizeof(struct in6_addr));
		} else {
			continue;
		}

		zebra_evpn_gw_macip_add(ifp, zevpn, &macaddr, &ip);
	}
	return 0;
}

static int ip_prefix_send_to_client(vrf_id_t vrf_id, struct prefix *p,
				    uint16_t cmd)
{
	struct zserv *client = NULL;
	struct stream *s = NULL;

	client = zserv_find_client(ZEBRA_ROUTE_BGP, 0);
	/* BGP may not be running. */
	if (!client)
		return 0;

	s = stream_new(ZEBRA_SMALL_PACKET_SIZE);

	zclient_create_header(s, cmd, vrf_id);
	stream_put(s, p, sizeof(struct prefix));

	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("Send ip prefix %pFX %s on vrf %s", p,
			   (cmd == ZEBRA_IP_PREFIX_ROUTE_ADD) ? "ADD" : "DEL",
			   vrf_id_to_name(vrf_id));

	if (cmd == ZEBRA_IP_PREFIX_ROUTE_ADD)
		client->prefixadd_cnt++;
	else
		client->prefixdel_cnt++;

	return zserv_send_message(client, s);
}

int zebra_evpn_advertise_subnet(struct zebra_evpn *zevpn, struct interface *ifp,
				int advertise)
{
	struct connected *c = NULL;
	struct ethaddr macaddr;

	memcpy(&macaddr.octet, ifp->hw_addr, ETH_ALEN);

	frr_each (if_connected, ifp->connected, c) {
		struct prefix p;

		memcpy(&p, c->address, sizeof(struct prefix));

		/* skip link local address */
		if (IN6_IS_ADDR_LINKLOCAL(&p.u.prefix6))
			continue;

		apply_mask(&p);
		if (advertise)
			ip_prefix_send_to_client(ifp->vrf->vrf_id, &p,
						 ZEBRA_IP_PREFIX_ROUTE_ADD);
		else
			ip_prefix_send_to_client(ifp->vrf->vrf_id, &p,
						 ZEBRA_IP_PREFIX_ROUTE_DEL);
	}
	return 0;
}

/*
 * zebra_evpn_gw_macip_add_to_client
 */
int zebra_evpn_gw_macip_add(struct interface *ifp, struct zebra_evpn *zevpn,
			    struct ethaddr *macaddr, struct ipaddr *ip)
{
	struct zebra_mac *mac = NULL;
	struct zebra_if *zif = NULL;
	struct zebra_vxlan_vni *vni;

	zif = zevpn->vxlan_if->info;
	if (!zif)
		return -1;

	vni = zebra_vxlan_if_vni_find(zif, zevpn->vni);

	zebra_evpn_mac_gw_macip_add(ifp, zevpn, ip, &mac, macaddr,
				    vni->access_vlan, true);

	return zebra_evpn_neigh_gw_macip_add(ifp, zevpn, ip, mac);
}

/*
 * zebra_evpn_gw_macip_del_from_client
 */
int zebra_evpn_gw_macip_del(struct interface *ifp, struct zebra_evpn *zevpn,
			    struct ipaddr *ip)
{
	struct zebra_neigh *n = NULL;
	struct zebra_mac *mac = NULL;

	/* If the neigh entry is not present nothing to do*/
	n = zebra_evpn_neigh_lookup(zevpn, ip);
	if (!n)
		return 0;

	/* mac entry should be present */
	mac = zebra_evpn_mac_lookup(zevpn, &n->emac);
	if (!mac) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("MAC %pEA doesn't exist for neigh %pIA on VNI %u",
				   &n->emac, ip, zevpn->vni);
		return -1;
	}

	/* If the entry is not local nothing to do*/
	if (!CHECK_FLAG(n->flags, ZEBRA_NEIGH_LOCAL))
		return -1;

	/* only need to delete the entry from bgp if we sent it before */
	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug(
			"%u:SVI %s(%u) VNI %u, sending GW MAC %pEA IP %pIA del to BGP",
			ifp->vrf->vrf_id, ifp->name, ifp->ifindex, zevpn->vni,
			&n->emac, ip);

	/* Remove neighbor from BGP. */
	zebra_evpn_neigh_send_del_to_client(zevpn->vni, &n->ip, &n->emac,
					    n->flags, ZEBRA_NEIGH_ACTIVE, false /*force*/);

	/* Delete this neighbor entry. */
	zebra_evpn_neigh_del(zevpn, n);

	/* see if the mac needs to be deleted as well*/
	if (mac)
		zebra_evpn_deref_ip2mac(zevpn, mac);

	return 0;
}

void zebra_evpn_gw_macip_del_for_evpn_hash(struct hash_bucket *bucket,
					   void *ctxt)
{
	struct zebra_evpn *zevpn = NULL;
	struct zebra_if *zif = NULL;
	struct zebra_vxlan_vni *vni = NULL;
	struct interface *vlan_if = NULL;
	struct interface *vrr_if = NULL;
	struct interface *ifp;

	/* Add primary SVI MAC*/
	zevpn = (struct zebra_evpn *)bucket->data;

	/* Global (Zvrf) advertise-default-gw is disabled,
	 * but zevpn advertise-default-gw is enabled
	 */
	if (zevpn->advertise_gw_macip) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("VNI: %u GW-MACIP enabled, retain gw-macip", zevpn->vni);
		return;
	}

	ifp = zevpn->vxlan_if;
	if (!ifp)
		return;
	zif = ifp->info;

	/* If down or not mapped to a bridge, we're done. */
	if (!if_is_operative(ifp) || !zif->brslave_info.br_if)
		return;

	vni = zebra_vxlan_if_vni_find(zif, zevpn->vni);
	if (!vni)
		return;

	vlan_if = zvni_map_to_svi(vni->access_vlan, zif->brslave_info.br_if);
	if (!vlan_if)
		return;

	/* Del primary MAC-IP */
	zebra_evpn_del_macip_for_intf(vlan_if, zevpn);

	/* Del VRR MAC-IP - if any*/
	vrr_if = zebra_get_vrr_intf_for_svi(vlan_if);
	if (vrr_if)
		zebra_evpn_del_macip_for_intf(vrr_if, zevpn);

	return;
}

void zebra_evpn_gw_macip_add_for_evpn_hash(struct hash_bucket *bucket,
					   void *ctxt)
{
	struct zebra_evpn *zevpn = NULL;
	struct zebra_if *zif = NULL;
	struct interface *vlan_if = NULL;
	struct interface *vrr_if = NULL;
	struct interface *ifp = NULL;
	struct zebra_vxlan_vni *vni = NULL;

	zevpn = (struct zebra_evpn *)bucket->data;

	ifp = zevpn->vxlan_if;
	if (!ifp)
		return;
	zif = ifp->info;

	/* If down or not mapped to a bridge, we're done. */
	if (!if_is_operative(ifp) || !zif->brslave_info.br_if)
		return;
	vni = zebra_vxlan_if_vni_find(zif, zevpn->vni);
	if (!vni)
		return;

	vlan_if = zvni_map_to_svi(vni->access_vlan, zif->brslave_info.br_if);
	if (!vlan_if)
		return;

	/* Add primary SVI MAC-IP */
	if (advertise_svi_macip_enabled(zevpn)
	    || advertise_gw_macip_enabled(zevpn))
		zebra_evpn_add_macip_for_intf(vlan_if, zevpn);

	if (advertise_gw_macip_enabled(zevpn)) {
		/* Add VRR MAC-IP - if any*/
		vrr_if = zebra_get_vrr_intf_for_svi(vlan_if);
		if (vrr_if)
			zebra_evpn_add_macip_for_intf(vrr_if, zevpn);
	}

	return;
}

void zebra_evpn_svi_macip_del_for_evpn_hash(struct hash_bucket *bucket,
					    void *ctxt)
{
	struct zebra_evpn *zevpn = NULL;
	struct zebra_if *zif = NULL;
	struct interface *vlan_if = NULL;
	struct zebra_vxlan_vni *vni = NULL;
	struct interface *ifp;

	/* Add primary SVI MAC*/
	zevpn = (struct zebra_evpn *)bucket->data;
	if (!zevpn)
		return;

	/* Global(vrf) advertise-svi-ip disabled, but zevpn advertise-svi-ip
	 * enabled
	 */
	if (zevpn->advertise_svi_macip) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("VNI: %u SVI-MACIP enabled, retain svi-macip",
				   zevpn->vni);
		return;
	}

	ifp = zevpn->vxlan_if;
	if (!ifp)
		return;
	zif = ifp->info;

	/* If down or not mapped to a bridge, we're done. */
	if (!if_is_operative(ifp) || !zif->brslave_info.br_if)
		return;

	vni = zebra_vxlan_if_vni_find(zif, zevpn->vni);
	if (!vni)
		return;

	vlan_if = zvni_map_to_svi(vni->access_vlan, zif->brslave_info.br_if);
	if (!vlan_if)
		return;

	/* Del primary MAC-IP */
	zebra_evpn_del_macip_for_intf(vlan_if, zevpn);

	return;
}

static int zebra_evpn_map_vlan_ns(struct ns *ns,
				  void *_in_param,
				  void **_p_zevpn)
{
	int found = 0;
	struct zebra_ns *zns = ns->info;
	struct route_node *rn;
	struct interface *br_if;
	struct zebra_evpn **p_zevpn = (struct zebra_evpn **)_p_zevpn;
	struct zebra_evpn *zevpn;
	struct interface *tmp_if = NULL;
	struct zebra_if *zif;
	struct zebra_from_svi_param *in_param =
		(struct zebra_from_svi_param *)_in_param;
	vlanid_t vid;
	vni_t vni_id = 0;
	uint8_t bridge_vlan_aware;

	assert(p_zevpn && in_param);

	br_if = in_param->br_if;
	assert(br_if);
	zif = in_param->zif;
	assert(zif);
	vid = in_param->vid;
	bridge_vlan_aware = in_param->bridge_vlan_aware;

	if (bridge_vlan_aware) {
		vni_id = zebra_l2_bridge_if_vni_find(zif, vid);
		if (vni_id)
			found = 1;
	} else {
		/*
		 * See if this interface (or interface plus VLAN Id) maps to a
		 * VxLAN
		 */
		/* TODO: Optimize with a hash. */
		for (rn = route_top(zns->if_table); rn; rn = route_next(rn)) {
			tmp_if = (struct interface *)rn->info;
			if (!tmp_if)
				continue;
			zif = tmp_if->info;
			if (!zif || zif->zif_type != ZEBRA_IF_VXLAN)
				continue;
			if (!if_is_operative(tmp_if))
				continue;

			if (zif->brslave_info.br_if != br_if)
				continue;

			vni_id = zebra_vxlan_if_access_vlan_vni_find(zif, br_if);
			if (vni_id) {
				found = 1;
				break;
			}
		}
	}

	if (!found)
		return NS_WALK_CONTINUE;

	zevpn = zebra_evpn_lookup(vni_id);
	*p_zevpn = zevpn;
	return NS_WALK_STOP;
}

/*
 * Map port or (port, VLAN) to an EVPN. This is invoked upon getting MAC
 * notifications, to see if they are of interest.
 */
struct zebra_evpn *zebra_evpn_map_vlan(struct interface *ifp,
				       struct interface *br_if, vlanid_t vid)
{
	struct zebra_if *zif;
	struct zebra_evpn **p_zevpn;
	struct zebra_evpn *zevpn = NULL;
	struct zebra_from_svi_param in_param;

	/* Determine if bridge is VLAN-aware or not */
	zif = br_if->info;
	assert(zif);
	in_param.bridge_vlan_aware = IS_ZEBRA_IF_BRIDGE_VLAN_AWARE(zif);
	in_param.vid = vid;
	in_param.br_if = br_if;
	in_param.zif = zif;
	p_zevpn = &zevpn;

	ns_walk_func(zebra_evpn_map_vlan_ns, (void *)&in_param, (void **)p_zevpn);
	return zevpn;
}

static int zebra_evpn_from_svi_ns(struct ns *ns,
				  void *_in_param,
				  void **_p_zevpn)
{
	struct zebra_ns *zns = ns->info;
	struct route_node *rn;
	struct interface *br_if;
	struct zebra_evpn **p_zevpn = (struct zebra_evpn **)_p_zevpn;
	struct zebra_evpn *zevpn;
	struct interface *tmp_if = NULL;
	struct zebra_if *zif;
	struct zebra_if *br_zif;
	struct zebra_l2_bridge_vlan *bvlan;
	struct zebra_from_svi_param *in_param =
		(struct zebra_from_svi_param *)_in_param;
	int found = 0;
	vni_t vni_id = 0;
	vlanid_t vid = 0;
	uint8_t bridge_vlan_aware;

	if (!in_param)
		return NS_WALK_STOP;

	br_if = in_param->br_if;
	zif = in_param->zif;
	assert(zif);
	bridge_vlan_aware = in_param->bridge_vlan_aware;
	vid = in_param->vid;
	br_zif = br_if->info;
	assert(br_zif);

	if (bridge_vlan_aware) {
		bvlan = zebra_l2_bridge_if_vlan_find(br_zif, vid);
		if (bvlan && bvlan->access_bd && bvlan->access_bd->vni) {
			found = 1;
			vni_id = bvlan->access_bd->vni;
		}
	} else {
		/* TODO: Optimize with a hash. */
		for (rn = route_top(zns->if_table); rn; rn = route_next(rn)) {
			tmp_if = (struct interface *)rn->info;
			if (!tmp_if)
				continue;
			zif = tmp_if->info;
			if (!zif || zif->zif_type != ZEBRA_IF_VXLAN)
				continue;
			if (!if_is_operative(tmp_if))
				continue;

			if (zif->brslave_info.br_if != br_if)
				continue;

			vni_id =
				zebra_vxlan_if_access_vlan_vni_find(zif, br_if);
			if (vni_id) {
				found = 1;
				break;
			}
		}
	}

	if (!found)
		return NS_WALK_CONTINUE;

	zevpn = zebra_evpn_lookup(vni_id);
	if (p_zevpn)
		*p_zevpn = zevpn;
	return NS_WALK_STOP;
}

/*
 * Map SVI and associated bridge to an EVPN. This is invoked upon getting
 * neighbor notifications, to see if they are of interest.
 */
struct zebra_evpn *zebra_evpn_from_svi(struct interface *ifp,
				       struct interface *br_if)
{
	struct zebra_evpn *zevpn = NULL;
	struct zebra_evpn **p_zevpn;
	struct zebra_if *zif;
	struct zebra_from_svi_param in_param;

	if (!br_if)
		return NULL;

	/* Make sure the linked interface is a bridge. */
	if (!IS_ZEBRA_IF_BRIDGE(br_if))
		return NULL;

	/* Determine if bridge is VLAN-aware or not */
	zif = br_if->info;
	assert(zif);
	in_param.bridge_vlan_aware = IS_ZEBRA_IF_BRIDGE_VLAN_AWARE(zif);
	in_param.vid = 0;

	if (in_param.bridge_vlan_aware) {
		struct zebra_l2info_vlan *vl;

		if (!IS_ZEBRA_IF_VLAN(ifp))
			return NULL;

		zif = ifp->info;
		assert(zif);
		vl = &zif->l2info.vl;
		in_param.vid = vl->vid;
	}

	in_param.br_if = br_if;
	in_param.zif = zif;
	p_zevpn = &zevpn;
	/* See if this interface (or interface plus VLAN Id) maps to a VxLAN */
	ns_walk_func(zebra_evpn_from_svi_ns, (void *)&in_param,
		     (void **)p_zevpn);
	return zevpn;
}

static int zvni_map_to_macvlan_ns(struct ns *ns, void *_in_param, void **_p_ifp)
{
	struct zebra_ns *zns = ns->info;
	struct zebra_from_svi_param *in_param =
		(struct zebra_from_svi_param *)_in_param;
	struct interface **p_ifp = (struct interface **)_p_ifp;
	struct route_node *rn;
	struct interface *tmp_if = NULL;
	struct zebra_if *zif;

	assert(in_param && p_ifp);

	/* Identify corresponding VLAN interface. */
	for (rn = route_top(zns->if_table); rn; rn = route_next(rn)) {
		tmp_if = (struct interface *)rn->info;
		/* Check oper status of the SVI. */
		if (!tmp_if || !if_is_operative(tmp_if))
			continue;
		zif = tmp_if->info;

		if (!zif || zif->zif_type != ZEBRA_IF_MACVLAN)
			continue;

		if (zif->link == in_param->svi_if) {
			*p_ifp = tmp_if;
			return NS_WALK_STOP;
		}
	}

	return NS_WALK_CONTINUE;
}

/* Map to MAC-VLAN interface corresponding to specified SVI interface.
 */
struct interface *zebra_evpn_map_to_macvlan(struct interface *br_if,
					    struct interface *svi_if)
{
	struct interface *tmp_if = NULL;
	struct zebra_if *zif;
	struct interface **p_ifp;
	struct zebra_from_svi_param in_param;

	/* Defensive check, caller expected to invoke only with valid bridge. */
	if (!br_if)
		return NULL;

	if (!svi_if) {
		zlog_debug("svi_if is not passed.");
		return NULL;
	}

	/* Determine if bridge is VLAN-aware or not */
	zif = br_if->info;
	assert(zif);

	in_param.vid = 0;
	in_param.br_if = br_if;
	in_param.zif = NULL;
	in_param.svi_if = svi_if;
	p_ifp = &tmp_if;

	/* Identify corresponding VLAN interface. */
	ns_walk_func(zvni_map_to_macvlan_ns, (void *)&in_param, (void **)p_ifp);
	return tmp_if;
}

/*
 * Uninstall MAC hash entry - called upon access VLAN change.
 */
static void zebra_evpn_uninstall_mac_hash(struct hash_bucket *bucket,
					  void *ctxt)
{
	struct zebra_mac *mac;
	struct mac_walk_ctx *wctx = ctxt;

	mac = (struct zebra_mac *)bucket->data;

	if (CHECK_FLAG(mac->flags, ZEBRA_MAC_REMOTE))
		zebra_evpn_rem_mac_uninstall(wctx->zevpn, mac, false);
}

/*
 * Install MAC hash entry - called upon access VLAN change.
 */
static void zebra_evpn_install_mac_hash(struct hash_bucket *bucket, void *ctxt)
{
	struct zebra_mac *mac;
	struct mac_walk_ctx *wctx = ctxt;

	mac = (struct zebra_mac *)bucket->data;

	if (CHECK_FLAG(mac->flags, ZEBRA_MAC_REMOTE))
		zebra_evpn_rem_mac_install(wctx->zevpn, mac, false);
}

/*
 * Uninstall remote MAC entries for this EVPN.
 */
void zebra_evpn_rem_mac_uninstall_all(struct zebra_evpn *zevpn)
{
	struct mac_walk_ctx wctx;

	if (!zevpn->mac_table)
		return;

	memset(&wctx, 0, sizeof(struct mac_walk_ctx));
	wctx.zevpn = zevpn;
	wctx.uninstall = 1;
	wctx.upd_client = 0;
	wctx.flags = ZEBRA_MAC_REMOTE;

	hash_iterate(zevpn->mac_table, zebra_evpn_uninstall_mac_hash, &wctx);
}

/*
 * Install remote MAC entries for this EVPN.
 */
void zebra_evpn_rem_mac_install_all(struct zebra_evpn *zevpn)
{
	struct mac_walk_ctx wctx;

	if (!zevpn->mac_table)
		return;

	memset(&wctx, 0, sizeof(struct mac_walk_ctx));
	wctx.zevpn = zevpn;
	wctx.uninstall = 0;
	wctx.upd_client = 0;
	wctx.flags = ZEBRA_MAC_REMOTE;

	hash_iterate(zevpn->mac_table, zebra_evpn_install_mac_hash, &wctx);
}

/*
 * Read and populate local MACs and neighbors corresponding to this EVPN.
 */
void zebra_evpn_read_mac_neigh(struct zebra_evpn *zevpn, struct interface *ifp)
{
	struct zebra_ns *zns;
	struct zebra_vrf *zvrf;
	struct zebra_if *zif;
	struct interface *vlan_if;
	struct zebra_vxlan_vni *vni;
	struct interface *vrr_if;

	zif = ifp->info;
	vni = zebra_vxlan_if_vni_find(zif, zevpn->vni);
	zvrf = zebra_vrf_lookup_by_id(zevpn->vrf_id);
	if (!zvrf || !zvrf->zns)
		return;
	zns = zvrf->zns;

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug(
			"Reading MAC FDB and Neighbors for intf %s(%u) VNI %u master %u",
			ifp->name, ifp->ifindex, zevpn->vni,
			zif->brslave_info.bridge_ifindex);

	macfdb_read_for_bridge(zns, ifp, zif->brslave_info.br_if,
			       vni->access_vlan);
	/* We need to specifically read and retrieve the entry for BUM handling
	 * via multicast, if any.
	 */
	macfdb_read_mcast_entry_for_vni(zns, ifp, zevpn->vni);
	vlan_if = zvni_map_to_svi(vni->access_vlan, zif->brslave_info.br_if);
	if (vlan_if) {
		/* Add SVI MAC */
		zebra_evpn_acc_bd_svi_mac_add(vlan_if);

		/* Add SVI MAC-IP */
		if (advertise_svi_macip_enabled(zevpn)
		    || advertise_gw_macip_enabled(zevpn))
			zebra_evpn_add_macip_for_intf(vlan_if, zevpn);

		/* Add VRR MAC-IP - if any*/
		if (advertise_gw_macip_enabled(zevpn)) {
			vrr_if = zebra_get_vrr_intf_for_svi(vlan_if);
			if (vrr_if)
				zebra_evpn_add_macip_for_intf(vrr_if, zevpn);
		}

		neigh_read_for_vlan(zns, vlan_if);
	}
}

/*
 * Hash function for EVPN.
 */
unsigned int zebra_evpn_hash_keymake(const void *p)
{
	const struct zebra_evpn *zevpn = p;

	return (jhash_1word(zevpn->vni, 0));
}

/*
 * Compare 2 evpn hash entries.
 */
bool zebra_evpn_hash_cmp(const void *p1, const void *p2)
{
	const struct zebra_evpn *zevpn1 = p1;
	const struct zebra_evpn *zevpn2 = p2;

	return (zevpn1->vni == zevpn2->vni);
}

int zebra_evpn_list_cmp(void *p1, void *p2)
{
	const struct zebra_evpn *zevpn1 = p1;
	const struct zebra_evpn *zevpn2 = p2;

	if (zevpn1->vni == zevpn2->vni)
		return 0;
	return (zevpn1->vni < zevpn2->vni) ? -1 : 1;
}

/*
 * Callback to allocate VNI hash entry.
 */
void *zebra_evpn_alloc(void *p)
{
	const struct zebra_evpn *tmp_vni = p;
	struct zebra_evpn *zevpn;

	zevpn = XCALLOC(MTYPE_ZEVPN, sizeof(struct zebra_evpn));
	zevpn->vni = tmp_vni->vni;
	return ((void *)zevpn);
}

/*
 * Look up EVPN hash entry.
 */
struct zebra_evpn *zebra_evpn_lookup(vni_t vni)
{
	struct zebra_vrf *zvrf;
	struct zebra_evpn tmp_vni;
	struct zebra_evpn *zevpn = NULL;

	zvrf = zebra_vrf_get_evpn();
	memset(&tmp_vni, 0, sizeof(tmp_vni));
	tmp_vni.vni = vni;
	zevpn = hash_lookup(zvrf->evpn_table, &tmp_vni);

	return zevpn;
}

/*
 * Add EVPN hash entry.
 */
struct zebra_evpn *zebra_evpn_add(vni_t vni)
{
	char buffer[80];
	struct zebra_vrf *zvrf;
	struct zebra_evpn tmp_zevpn;
	struct zebra_evpn *zevpn = NULL;

	zvrf = zebra_vrf_get_evpn();
	memset(&tmp_zevpn, 0, sizeof(tmp_zevpn));
	tmp_zevpn.vni = vni;
	zevpn = hash_get(zvrf->evpn_table, &tmp_zevpn, zebra_evpn_alloc);

	zebra_evpn_es_evi_init(zevpn);

	snprintf(buffer, sizeof(buffer), "Zebra EVPN MAC Table vni: %u", vni);
	/* Create hash table for MAC */
	zevpn->mac_table = zebra_mac_db_create(buffer);

	snprintf(buffer, sizeof(buffer), "Zebra EVPN Neighbor Table vni: %u", vni);
	/* Create hash table for neighbors */
	zevpn->neigh_table = zebra_neigh_db_create(buffer);

	return zevpn;
}

/*
 * Delete EVPN hash entry.
 */
int zebra_evpn_del(struct zebra_evpn *zevpn)
{
	struct zebra_vrf *zvrf;
	struct zebra_evpn *tmp_zevpn;

	zvrf = zebra_vrf_get_evpn();

	zevpn->svi_if = NULL;

	/* Free the neighbor hash table. */
	hash_free(zevpn->neigh_table);
	zevpn->neigh_table = NULL;

	/* Free the MAC hash table. */
	hash_free(zevpn->mac_table);
	zevpn->mac_table = NULL;

	/* Remove references to the zevpn in the MH databases */
	if (zevpn->vxlan_if)
		zebra_evpn_vxl_evpn_set(zevpn->vxlan_if->info, zevpn, false);
	zebra_evpn_es_evi_cleanup(zevpn);

	/* Free the EVPN hash entry and allocated memory. */
	tmp_zevpn = hash_release(zvrf->evpn_table, zevpn);
	XFREE(MTYPE_ZEVPN, tmp_zevpn);

	return 0;
}

/*
 * Inform BGP about local EVPN addition.
 */
int zebra_evpn_send_add_to_client(struct zebra_evpn *zevpn)
{
	struct zserv *client;
	struct stream *s;
	ifindex_t svi_index;
	int rc;

	client = zserv_find_client(ZEBRA_ROUTE_BGP, 0);
	/* BGP may not be running. */
	if (!client)
		return 0;

	svi_index = zevpn->svi_if ? zevpn->svi_if->ifindex : 0;

	s = stream_new(ZEBRA_SMALL_PACKET_SIZE);

	zclient_create_header(s, ZEBRA_VNI_ADD, zebra_vrf_get_evpn_id());
	stream_putl(s, zevpn->vni);
	stream_put_in_addr(s, &zevpn->local_vtep_ip);
	stream_put(s, &zevpn->vrf_id, sizeof(vrf_id_t)); /* tenant vrf */
	stream_put_in_addr(s, &zevpn->mcast_grp);
	stream_put(s, &svi_index, sizeof(ifindex_t));

	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug(
			"Send EVPN_ADD %u %pI4 tenant vrf %s(%u) SVI index %u to %s",
			zevpn->vni, &zevpn->local_vtep_ip,
			vrf_id_to_name(zevpn->vrf_id), zevpn->vrf_id,
			(zevpn->svi_if ? zevpn->svi_if->ifindex : 0),
			zebra_route_string(client->proto));

	client->vniadd_cnt++;
	rc = zserv_send_message(client, s);

	if (!CHECK_FLAG(zevpn->flags, ZEVPN_READY_FOR_BGP)) {
		SET_FLAG(zevpn->flags, ZEVPN_READY_FOR_BGP);
		/* once the EVPN is sent the ES-EVIs can also be replayed
		 * to BGP
		 */
		zebra_evpn_update_all_es(zevpn);
	}
	return rc;
}

/*
 * Inform BGP about local EVPN deletion.
 */
int zebra_evpn_send_del_to_client(struct zebra_evpn *zevpn)
{
	struct zserv *client;
	struct stream *s;

	client = zserv_find_client(ZEBRA_ROUTE_BGP, 0);
	/* BGP may not be running. */
	if (!client)
		return 0;

	if (CHECK_FLAG(zevpn->flags, ZEVPN_READY_FOR_BGP)) {
		UNSET_FLAG(zevpn->flags, ZEVPN_READY_FOR_BGP);
		/* the ES-EVIs must be removed from BGP before the EVPN is */
		zebra_evpn_update_all_es(zevpn);
	}

	s = stream_new(ZEBRA_SMALL_PACKET_SIZE);
	stream_reset(s);

	zclient_create_header(s, ZEBRA_VNI_DEL, zebra_vrf_get_evpn_id());
	stream_putl(s, zevpn->vni);

	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("Send EVPN_DEL %u to %s", zevpn->vni,
			   zebra_route_string(client->proto));

	client->vnidel_cnt++;
	return zserv_send_message(client, s);
}

/*
 * See if remote VTEP matches with prefix.
 */
static int zebra_evpn_vtep_match(struct in_addr *vtep_ip,
				 struct zebra_vtep *zvtep)
{
	return (IPV4_ADDR_SAME(vtep_ip, &zvtep->vtep_ip));
}

/*
 * Locate remote VTEP in EVPN hash table.
 */
struct zebra_vtep *zebra_evpn_vtep_find(struct zebra_evpn *zevpn,
					struct in_addr *vtep_ip)
{
	struct zebra_vtep *zvtep;

	if (!zevpn)
		return NULL;

	for (zvtep = zevpn->vteps; zvtep; zvtep = zvtep->next) {
		if (zebra_evpn_vtep_match(vtep_ip, zvtep))
			break;
	}

	return zvtep;
}

/*
 * Add remote VTEP to EVPN hash table.
 */
struct zebra_vtep *zebra_evpn_vtep_add(struct zebra_evpn *zevpn,
				       struct in_addr *vtep_ip,
				       int flood_control)

{
	struct zebra_vtep *zvtep;

	zvtep = XCALLOC(MTYPE_ZEVPN_VTEP, sizeof(struct zebra_vtep));

	zvtep->vtep_ip = *vtep_ip;
	zvtep->flood_control = flood_control;

	if (zevpn->vteps)
		zevpn->vteps->prev = zvtep;
	zvtep->next = zevpn->vteps;
	zevpn->vteps = zvtep;

	return zvtep;
}

/*
 * Remove remote VTEP from EVPN hash table.
 */
int zebra_evpn_vtep_del(struct zebra_evpn *zevpn, struct zebra_vtep *zvtep)
{
	if (zvtep->next)
		zvtep->next->prev = zvtep->prev;
	if (zvtep->prev)
		zvtep->prev->next = zvtep->next;
	else
		zevpn->vteps = zvtep->next;

	zvtep->prev = zvtep->next = NULL;
	XFREE(MTYPE_ZEVPN_VTEP, zvtep);

	return 0;
}

/*
 * Delete all remote VTEPs for this EVPN (upon VNI delete). Also
 * uninstall from kernel if asked to.
 */
int zebra_evpn_vtep_del_all(struct zebra_evpn *zevpn, int uninstall)
{
	struct zebra_vtep *zvtep, *zvtep_next;

	if (!zevpn)
		return -1;

	for (zvtep = zevpn->vteps; zvtep; zvtep = zvtep_next) {
		zvtep_next = zvtep->next;
		if (uninstall)
			zebra_evpn_vtep_uninstall(zevpn, &zvtep->vtep_ip);
		zebra_evpn_vtep_del(zevpn, zvtep);
	}

	return 0;
}

/*
 * Install remote VTEP into the kernel if the remote VTEP has asked
 * for head-end-replication.
 */
int zebra_evpn_vtep_install(struct zebra_evpn *zevpn, struct zebra_vtep *zvtep)
{
	if (is_vxlan_flooding_head_end() &&
	    (zvtep->flood_control == VXLAN_FLOOD_HEAD_END_REPL)) {
		if (ZEBRA_DPLANE_REQUEST_FAILURE ==
		    dplane_vtep_add(zevpn->vxlan_if, &zvtep->vtep_ip, zevpn->vni))
			return -1;
	}

	return 0;
}

/*
 * Uninstall remote VTEP from the kernel.
 */
int zebra_evpn_vtep_uninstall(struct zebra_evpn *zevpn, struct in_addr *vtep_ip)
{
	if (!zevpn->vxlan_if) {
		zlog_debug("VNI %u hash %p couldn't be uninstalled - no intf",
			   zevpn->vni, zevpn);
		return -1;
	}

	if (ZEBRA_DPLANE_REQUEST_FAILURE ==
	    dplane_vtep_delete(zevpn->vxlan_if, vtep_ip, zevpn->vni))
		return -1;

	return 0;
}

/*
 * Install or uninstall flood entries in the kernel corresponding to
 * remote VTEPs. This is invoked upon change to BUM handling.
 */
void zebra_evpn_handle_flooding_remote_vteps(struct hash_bucket *bucket,
					     void *zvrf)
{
	struct zebra_evpn *zevpn;
	struct zebra_vtep *zvtep;

	zevpn = (struct zebra_evpn *)bucket->data;
	if (!zevpn)
		return;

	for (zvtep = zevpn->vteps; zvtep; zvtep = zvtep->next) {
		if (is_vxlan_flooding_head_end())
			zebra_evpn_vtep_install(zevpn, zvtep);
		else
			zebra_evpn_vtep_uninstall(zevpn, &zvtep->vtep_ip);
	}
}

/*
 * Cleanup EVPN/VTEP and update kernel
 */
void zebra_evpn_cleanup_all(struct hash_bucket *bucket, void *arg)
{
	struct zebra_evpn *zevpn = NULL;

	zevpn = (struct zebra_evpn *)bucket->data;

	/* Free up all neighbors and MACs, if any. */
	zebra_evpn_neigh_del_all(zevpn, 1, 0, DEL_ALL_NEIGH);
	zebra_evpn_mac_del_all(zevpn, 1, 0, DEL_ALL_MAC);

	/* Free up all remote VTEPs, if any. */
	zebra_evpn_vtep_del_all(zevpn, 1);

	/* Delete the hash entry. */
	zebra_evpn_del(zevpn);
}

static void zebra_evpn_process_sync_macip_add(struct zebra_evpn *zevpn,
					      const struct ethaddr *macaddr,
					      uint16_t ipa_len,
					      const struct ipaddr *ipaddr,
					      uint8_t flags, uint32_t seq,
					      const esi_t *esi)
{
	char ipbuf[INET6_ADDRSTRLEN];
	bool sticky;
	bool remote_gw;
	struct zebra_neigh *n = NULL;
	struct zebra_mac *mac = NULL;

	sticky = !!CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_STICKY);
	remote_gw = !!CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_GW);
	/* if sticky or remote-gw ignore updates from the peer */
	if (sticky || remote_gw) {
		if (IS_ZEBRA_DEBUG_VXLAN || IS_ZEBRA_DEBUG_EVPN_MH_NEIGH
		    || IS_ZEBRA_DEBUG_EVPN_MH_MAC)
			zlog_debug(
				"Ignore sync-macip vni %u mac %pEA%s%s%s%s",
				zevpn->vni,
				macaddr,
				ipa_len ? " IP " : "",
				ipa_len ? ipaddr2str(ipaddr, ipbuf, sizeof(ipbuf)) : "",
				sticky ? " sticky" : "",
				remote_gw ? " remote_gw" : "");
		return;
	}

	if (!ipa_len) {
		/* MAC update */
		(void)zebra_evpn_proc_sync_mac_update(zevpn, macaddr, ipa_len,
						      ipaddr, flags, seq, esi);
	} else {
		/* MAC-IP update */
		mac = zebra_evpn_mac_lookup(zevpn, macaddr);
		if (!mac) {
			mac = zebra_evpn_proc_sync_mac_update(zevpn, macaddr,
							      ipa_len, ipaddr, flags, seq, esi);
		}
		if (!mac)
			return;

		n = zebra_evpn_neigh_lookup(zevpn, ipaddr);
		if (n && !zebra_evpn_neigh_is_bgp_seq_ok(zevpn, n, macaddr, seq, true))
			return;

		zebra_evpn_proc_sync_neigh_update(zevpn, n, ipa_len, ipaddr,
						  flags, seq, esi, mac);
	}
}

/************************** remote mac-ip handling **************************/
/* Process a remote MACIP add from BGP. */
void zebra_evpn_rem_macip_add(vni_t vni, const struct ethaddr *macaddr,
			      uint16_t ipa_len, const struct ipaddr *ipaddr,
			      uint8_t flags, uint32_t seq,
			      struct in_addr vtep_ip, const esi_t *esi)
{
	struct zebra_evpn *zevpn;
	struct zebra_vtep *zvtep;
	struct zebra_mac *mac = NULL;
	struct interface *ifp = NULL;
	struct zebra_if *zif = NULL;
	struct zebra_vrf *zvrf;

	/* Locate EVPN hash entry - expected to exist. */
	zevpn = zebra_evpn_lookup(vni);
	if (!zevpn) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("Unknown VNI %u upon remote MACIP ADD", vni);
		return;
	}

	ifp = zevpn->vxlan_if;
	if (ifp)
		zif = ifp->info;
	if (!ifp || !if_is_operative(ifp) || !zif || !zif->brslave_info.br_if) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"Ignoring remote MACIP ADD VNI %u, invalid interface state or info",
				vni);
		return;
	}

	/* Type-2 routes from another PE can be interpreted as remote or
	 * SYNC based on the destination ES -
	 * SYNC - if ES is local
	 * REMOTE - if ES is not local
	 */
	if (CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_SYNC_PATH)) {
		struct zebra_evpn_es *es;

		es = zebra_evpn_es_find(esi);
		if (es && CHECK_FLAG(es->flags, ZEBRA_EVPNES_READY_FOR_BGP)) {
			zebra_evpn_process_sync_macip_add(zevpn, macaddr,
							  ipa_len, ipaddr, flags, seq, esi);
		} else {
			if (IS_ZEBRA_DEBUG_EVPN_MH_ES) {
				char esi_str[ESI_STR_LEN];

				esi_to_str(esi, esi_str, sizeof(esi_str));
				zlog_debug("Ignore sync-macip add; ES %s is not ready", esi_str);
			}
		}

		return;
	}

	/* The remote VTEP specified should normally exist, but it is
	 * possible that when peering comes up, peer may advertise MACIP
	 * routes before advertising type-3 routes.
	 */
	if (vtep_ip.s_addr) {
		zvtep = zebra_evpn_vtep_find(zevpn, &vtep_ip);
		if (!zvtep) {
			zvtep = zebra_evpn_vtep_add(zevpn, &vtep_ip, VXLAN_FLOOD_DISABLED);
			if (!zvtep) {
				flog_err(
					EC_ZEBRA_VTEP_ADD_FAILED,
					"Failed to add remote VTEP, VNI %u zevpn %p upon remote MACIP ADD",
					vni, zevpn);
				return;
			}

			zebra_evpn_vtep_install(zevpn, zvtep);
		}
	}

	zvrf = zebra_vrf_get_evpn();
	if (!zvrf)
		return;

	if (!ipa_len) {
		/* MAC update */
		zebra_evpn_mac_remote_macip_add(zevpn, zvrf, macaddr, vtep_ip,
						flags, seq, esi);
	} else {
		/* MAC-IP update
		 * Add auto MAC if it doesn't exist.
		 */
		mac = zebra_evpn_mac_lookup(zevpn, macaddr);
		if (!mac) {
			mac = zebra_evpn_mac_add_auto(zevpn, macaddr);

			if (IS_ZEBRA_DEBUG_VXLAN)
				zlog_debug(
					"Neigh %pIA: MAC %pEA not found, Auto MAC created",
					ipaddr, macaddr);
		}

		zebra_evpn_neigh_remote_macip_add(zevpn, zvrf, ipaddr, mac,
						  vtep_ip, flags, seq);
	}
}

/* Process a remote MACIP delete from BGP. */
void zebra_evpn_rem_macip_del(vni_t vni, const struct ethaddr *macaddr,
			      uint16_t ipa_len, const struct ipaddr *ipaddr,
			      struct in_addr vtep_ip)
{
	struct zebra_evpn *zevpn;
	struct zebra_mac *mac = NULL;
	struct zebra_neigh *n = NULL;
	struct interface *ifp = NULL;
	struct zebra_if *zif = NULL;
	struct zebra_ns *zns;
	struct zebra_vxlan_vni *vnip;
	struct zebra_vrf *zvrf;
	char buf1[INET6_ADDRSTRLEN];

	/* Locate EVPN hash entry - expected to exist. */
	zevpn = zebra_evpn_lookup(vni);
	if (!zevpn) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("Unknown VNI %u upon remote MACIP DEL", vni);
		return;
	}

	ifp = zevpn->vxlan_if;
	if (ifp)
		zif = ifp->info;
	if (!ifp || !if_is_operative(ifp) || !zif || !zif->brslave_info.br_if) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"Ignoring remote MACIP DEL VNI %u, invalid interface state or info",
				vni);
		return;
	}
	zns = zebra_ns_lookup(NS_DEFAULT);
	vnip = zebra_vxlan_if_vni_find(zif, vni);
	if (!vnip) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("VNI %u not in interface upon remote MACIP DEL", vni);
		return;
	}

	mac = zebra_evpn_mac_lookup(zevpn, macaddr);
	if (ipa_len)
		n = zebra_evpn_neigh_lookup(zevpn, ipaddr);

	if (n && !mac) {
		zlog_warn(
			"Failed to locate MAC %pEA for Neigh %pIA VNI %u upon remote MACIP DEL",
			macaddr, ipaddr, vni);
		return;
	}

	/* If the remote mac or neighbor doesn't exist there is nothing
	 * more to do. Otherwise, uninstall the entry and then remove it.
	 */
	if (!mac && !n) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"Failed to locate MAC %pEA & Neigh %pIA VNI %u upon remote MACIP DEL",
				macaddr, ipaddr, vni);
		return;
	}

	zvrf = zevpn->vxlan_if->vrf->info;

	/* Ignore the delete if this mac is a gateway mac-ip */
	if (CHECK_FLAG(mac->flags, ZEBRA_MAC_LOCAL)
	    && CHECK_FLAG(mac->flags, ZEBRA_MAC_DEF_GW)) {
		zlog_warn(
			"Ignore remote MACIP DEL VNI %u MAC %pEA%s%s as MAC is already configured as gateway MAC",
			vni, macaddr,
			ipa_len ? " IP " : "",
			ipa_len ? ipaddr2str(ipaddr, buf1, sizeof(buf1)) : "");
		return;
	}

	/* Uninstall remote neighbor or MAC. */
	if (n)
		zebra_evpn_neigh_remote_uninstall(zevpn, zvrf, n, mac, ipaddr);
	else {
		/* DAD: when MAC is freeze state as remote learn event,
		 * remote mac-ip delete event is received will result in freeze
		 * entry removal, first fetch kernel for the same entry present
		 * as LOCAL and reachable, avoid deleting this entry instead
		 * use kerenel local entry to update during unfreeze time.
		 */
		if (zvrf->dad_freeze
		    && CHECK_FLAG(mac->flags, ZEBRA_MAC_DUPLICATE)
		    && CHECK_FLAG(mac->flags, ZEBRA_MAC_REMOTE)) {
			if (IS_ZEBRA_DEBUG_VXLAN)
				zlog_debug(
					"%s: MAC %pEA (flags 0x%x) is remote and duplicate, read kernel for local entry",
					__func__, macaddr, mac->flags);
			macfdb_read_specific_mac(zns, zif->brslave_info.br_if,
						 macaddr, vnip->access_vlan);
		}

		if (CHECK_FLAG(mac->flags, ZEBRA_MAC_LOCAL)) {
			if (!ipa_len)
				zebra_evpn_sync_mac_del(mac);
		} else if (CHECK_FLAG(mac->flags, ZEBRA_NEIGH_REMOTE)) {
			zebra_evpn_rem_mac_del(zevpn, mac);
		}
	}
}

/************************** EVPN BGP config management ************************/
void zebra_evpn_cfg_cleanup(struct hash_bucket *bucket, void *ctxt)
{
	struct zebra_evpn *zevpn = NULL;

	zevpn = (struct zebra_evpn *)bucket->data;
	zevpn->advertise_gw_macip = 0;
	zevpn->advertise_svi_macip = 0;
	zevpn->advertise_subnet = 0;

	zebra_evpn_neigh_del_all(zevpn, 1, 0,
				 DEL_REMOTE_NEIGH | DEL_REMOTE_NEIGH_FROM_VTEP);
	zebra_evpn_mac_del_all(zevpn, 1, 0,
			       DEL_REMOTE_MAC | DEL_REMOTE_MAC_FROM_VTEP);
	zebra_evpn_vtep_del_all(zevpn, 1);
}
