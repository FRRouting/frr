// SPDX-License-Identifier: GPL-2.0-or-later
/* MPLS/BGP L3VPN MIB
 * Copyright (C) 2020 Volta Networks Inc
 */

#include <zebra.h>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include "if.h"
#include "log.h"
#include "prefix.h"
#include "command.h"
#include "frrevent.h"
#include "smux.h"
#include "filter.h"
#include "hook.h"
#include "libfrr.h"
#include "lib/version.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_mplsvpn_snmp.h"

#define BGP_mplsvpn_notif_enable_true 1
#define BGP_mplsvpn_notif_enable_false 2

/* MPLSL3VPN MIB described in RFC4382 */
#define MPLSL3VPNMIB 1, 3, 6, 1, 2, 1, 10, 166, 11

/* MPLSL3VPN Scalars */
#define MPLSL3VPNCONFIGUREDVRFS 1
#define MPLSL3VPNACTIVEVRFS 2
#define MPLSL3VPNCONNECTEDINTERFACES 3
#define MPLSL3VPNNOTIFICATIONENABLE 4
#define MPLSL3VPNCONFMAXPOSSRTS 5
#define MPLSL3VPNVRFCONFRTEMXTHRSHTIME 6
#define MPLSL3VPNILLLBLRCVTHRSH 7

/* MPLSL3VPN IFConf Table */
#define MPLSL3VPNIFVPNCLASSIFICATION 1
#define MPLSL3VPNIFCONFSTORAGETYPE 2
#define MPLSL3VPNIFCONFROWSTATUS 3

/* MPLSL3VPN VRF Table */
#define MPLSL3VPNVRFVPNID 1
#define MPLSL3VPNVRFDESC 2
#define MPLSL3VPNVRFRD 3
#define MPLSL3VPNVRFCREATIONTIME 4
#define MPLSL3VPNVRFOPERSTATUS 5
#define MPLSL3VPNVRFACTIVEINTERFACES 6
#define MPLSL3VPNVRFASSOCIATEDINTERFACES 7
#define MPLSL3VPNVRFCONFMIDRTETHRESH 8
#define MPLSL3VPNVRFCONFHIGHRTETHRSH 9
#define MPLSL3VPNVRFCONFMAXROUTES 10
#define MPLSL3VPNVRFCONFLASTCHANGED 11
#define MPLSL3VPNVRFCONFROWSTATUS 12
#define MPLSL3VPNVRFCONFADMINSTATUS 13
#define MPLSL3VPNVRFCONFSTORAGETYPE 14

/* MPLSL3VPN RT Table */
#define MPLSL3VPNVRFRT 1
#define MPLSL3VPNVRFRTDESCR 2
#define MPLSL3VPNVRFRTROWSTATUS 3
#define MPLSL3VPNVRFRTSTORAGETYPE 4

/* MPLSL3VPN PERF Table */
#define MPLSL3VPNVRFPERFROUTESADDED 1
#define MPLSL3VPNVRFPERFROUTESDELETED 2
#define MPLSL3VPNVRFPERFCURRNUMROUTES 3

/* MPLSL3VPN RTE Table */
#define MPLSL3VPNVRFRTEINETCIDRDESTTYPE 1
#define MPLSL3VPNVRFRTEINETCIDRDEST 2
#define MPLSL3VPNVRFRTEINETCIDRPFXLEN 3
#define MPLSL3VPNVRFRTEINETCIDRPOLICY 4
#define MPLSL3VPNVRFRTEINETCIDRNHOPTYPE 5
#define MPLSL3VPNVRFRTEINETCIDRNEXTHOP 6
#define MPLSL3VPNVRFRTEINETCIDRIFINDEX 7
#define MPLSL3VPNVRFRTEINETCIDRTYPE 8
#define MPLSL3VPNVRFRTEINETCIDRPROTO 9
#define MPLSL3VPNVRFRTEINETCIDRAGE 10
#define MPLSL3VPNVRFRTEINETCIDRNEXTHOPAS 11
#define MPLSL3VPNVRFRTEINETCIDRMETRIC1 12
#define MPLSL3VPNVRFRTEINETCIDRMETRIC2 13
#define MPLSL3VPNVRFRTEINETCIDRMETRIC3 14
#define MPLSL3VPNVRFRTEINETCIDRMETRIC4 15
#define MPLSL3VPNVRFRTEINETCIDRMETRIC5 16
#define MPLSL3VPNVRFRTEINETCIDRXCPOINTER 17
#define MPLSL3VPNVRFRTEINETCIDRSTATUS 18

/* BGP Trap */
#define MPLSL3VPNVRFUP 1
#define MPLSL3VPNDOWN 2

/* SNMP value hack. */
#define INTEGER ASN_INTEGER
#define INTEGER32 ASN_INTEGER
#define COUNTER32 ASN_COUNTER
#define OCTET_STRING ASN_OCTET_STR
#define IPADDRESS ASN_IPADDRESS
#define GAUGE32 ASN_UNSIGNED
#define TIMETICKS ASN_TIMETICKS
#define OID ASN_OBJECT_ID

/* Declare static local variables for convenience. */
SNMP_LOCAL_VARIABLES

#define RT_PREAMBLE_SIZE 20

/* BGP-MPLS-MIB instances */
static oid mpls_l3vpn_oid[] = {MPLSL3VPNMIB};
static oid mpls_l3vpn_trap_oid[] = {MPLSL3VPNMIB, 0};
static char rd_buf[RD_ADDRSTRLEN];
/* Notifications enabled by default */
static uint8_t bgp_mplsvpn_notif_enable = SNMP_TRUE;
static oid mpls_l3vpn_policy_oid[2] = {0, 0};
static const char *empty_nhop = "";
char rt_description[VRF_NAMSIZ + RT_PREAMBLE_SIZE];

static uint8_t *mplsL3vpnConfiguredVrfs(struct variable *, oid[], size_t *, int,
					size_t *, WriteMethod **);

static uint8_t *mplsL3vpnActiveVrfs(struct variable *, oid[], size_t *, int,
				    size_t *, WriteMethod **);

static uint8_t *mplsL3vpnConnectedInterfaces(struct variable *, oid[], size_t *,
					     int, size_t *, WriteMethod **);

static uint8_t *mplsL3vpnNotificationEnable(struct variable *, oid[], size_t *,
					    int, size_t *, WriteMethod **);

static uint8_t *mplsL3vpnVrfConfMaxPossRts(struct variable *, oid[], size_t *,
					   int, size_t *, WriteMethod **);

static uint8_t *mplsL3vpnVrfConfRteMxThrshTime(struct variable *, oid[],
					       size_t *, int, size_t *,
					       WriteMethod **);

static uint8_t *mplsL3vpnIllLblRcvThrsh(struct variable *, oid[], size_t *, int,
					size_t *, WriteMethod **);

static uint8_t *mplsL3vpnVrfTable(struct variable *, oid[], size_t *, int,
				  size_t *, WriteMethod **);

static uint8_t *mplsL3vpnVrfRtTable(struct variable *, oid[], size_t *, int,
				    size_t *, WriteMethod **);

static uint8_t *mplsL3vpnIfConfTable(struct variable *, oid[], size_t *, int,
				     size_t *, WriteMethod **);

static uint8_t *mplsL3vpnPerfTable(struct variable *, oid[], size_t *, int,
				   size_t *, WriteMethod **);

static uint8_t *mplsL3vpnRteTable(struct variable *, oid[], size_t *, int,
				  size_t *, WriteMethod **);


static struct variable mpls_l3vpn_variables[] = {
	/* BGP version. */
	{MPLSL3VPNCONFIGUREDVRFS,
	 GAUGE32,
	 RONLY,
	 mplsL3vpnConfiguredVrfs,
	 3,
	 {1, 1, 1} },
	{MPLSL3VPNACTIVEVRFS,
	 GAUGE32,
	 RONLY,
	 mplsL3vpnActiveVrfs,
	 3,
	 {1, 1, 2} },
	{MPLSL3VPNCONNECTEDINTERFACES,
	 GAUGE32,
	 RONLY,
	 mplsL3vpnConnectedInterfaces,
	 3,
	 {1, 1, 3} },
	{MPLSL3VPNNOTIFICATIONENABLE,
	 INTEGER,
	 RWRITE,
	 mplsL3vpnNotificationEnable,
	 3,
	 {1, 1, 4} },
	{MPLSL3VPNCONFMAXPOSSRTS,
	 GAUGE32,
	 RONLY,
	 mplsL3vpnVrfConfMaxPossRts,
	 3,
	 {1, 1, 5} },
	{MPLSL3VPNVRFCONFRTEMXTHRSHTIME,
	 GAUGE32,
	 RONLY,
	 mplsL3vpnVrfConfRteMxThrshTime,
	 3,
	 {1, 1, 6} },
	{MPLSL3VPNILLLBLRCVTHRSH,
	 GAUGE32,
	 RONLY,
	 mplsL3vpnIllLblRcvThrsh,
	 3,
	 {1, 1, 7} },

	/* Ifconf Table */
	{MPLSL3VPNIFVPNCLASSIFICATION,
	 INTEGER,
	 RONLY,
	 mplsL3vpnIfConfTable,
	 5,
	 {1, 2, 1, 1, 2} },
	{MPLSL3VPNIFCONFSTORAGETYPE,
	 INTEGER,
	 RONLY,
	 mplsL3vpnIfConfTable,
	 5,
	 {1, 2, 1, 1, 4} },
	{MPLSL3VPNIFCONFROWSTATUS,
	 INTEGER,
	 RONLY,
	 mplsL3vpnIfConfTable,
	 5,
	 {1, 2, 1, 1, 5} },

	/* mplsL3VpnVrf Table */
	{MPLSL3VPNVRFVPNID,
	 OCTET_STRING,
	 RONLY,
	 mplsL3vpnVrfTable,
	 5,
	 {1, 2, 2, 1, 2} },
	{MPLSL3VPNVRFDESC,
	 OCTET_STRING,
	 RONLY,
	 mplsL3vpnVrfTable,
	 5,
	 {1, 2, 2, 1, 3} },
	{MPLSL3VPNVRFRD,
	 OCTET_STRING,
	 RONLY,
	 mplsL3vpnVrfTable,
	 5,
	 {1, 2, 2, 1, 4} },
	{MPLSL3VPNVRFCREATIONTIME,
	 TIMETICKS,
	 RONLY,
	 mplsL3vpnVrfTable,
	 5,
	 {1, 2, 2, 1, 5} },
	{MPLSL3VPNVRFOPERSTATUS,
	 INTEGER,
	 RONLY,
	 mplsL3vpnVrfTable,
	 5,
	 {1, 2, 2, 1, 6} },
	{MPLSL3VPNVRFACTIVEINTERFACES,
	 GAUGE32,
	 RONLY,
	 mplsL3vpnVrfTable,
	 5,
	 {1, 2, 2, 1, 7} },
	{MPLSL3VPNVRFASSOCIATEDINTERFACES,
	 GAUGE32,
	 RONLY,
	 mplsL3vpnVrfTable,
	 5,
	 {1, 2, 2, 1, 8} },
	{MPLSL3VPNVRFCONFMIDRTETHRESH,
	 GAUGE32,
	 RONLY,
	 mplsL3vpnVrfTable,
	 5,
	 {1, 2, 2, 1, 9} },
	{MPLSL3VPNVRFCONFHIGHRTETHRSH,
	 GAUGE32,
	 RONLY,
	 mplsL3vpnVrfTable,
	 5,
	 {1, 2, 2, 1, 10} },
	{MPLSL3VPNVRFCONFMAXROUTES,
	 GAUGE32,
	 RONLY,
	 mplsL3vpnVrfTable,
	 5,
	 {1, 2, 2, 1, 11} },
	{MPLSL3VPNVRFCONFLASTCHANGED,
	 TIMETICKS,
	 RONLY,
	 mplsL3vpnVrfTable,
	 5,
	 {1, 2, 2, 1, 12} },
	{MPLSL3VPNVRFCONFROWSTATUS,
	 INTEGER,
	 RONLY,
	 mplsL3vpnVrfTable,
	 5,
	 {1, 2, 2, 1, 13} },
	{MPLSL3VPNVRFCONFADMINSTATUS,
	 INTEGER,
	 RONLY,
	 mplsL3vpnVrfTable,
	 5,
	 {1, 2, 2, 1, 14} },
	{MPLSL3VPNVRFCONFSTORAGETYPE,
	 INTEGER,
	 RONLY,
	 mplsL3vpnVrfTable,
	 5,
	 {1, 2, 2, 1, 15} },

	/* mplsL3vpnVrfRt Table */
	{MPLSL3VPNVRFRT,
	 OCTET_STRING,
	 RONLY,
	 mplsL3vpnVrfRtTable,
	 5,
	 {1, 2, 3, 1, 4} },
	{MPLSL3VPNVRFRTDESCR,
	 OCTET_STRING,
	 RONLY,
	 mplsL3vpnVrfRtTable,
	 5,
	 {1, 2, 3, 1, 5} },
	{MPLSL3VPNVRFRTROWSTATUS,
	 INTEGER,
	 RONLY,
	 mplsL3vpnVrfRtTable,
	 5,
	 {1, 2, 3, 1, 6} },
	{MPLSL3VPNVRFRTSTORAGETYPE,
	 INTEGER,
	 RONLY,
	 mplsL3vpnVrfRtTable,
	 5,
	 {1, 2, 3, 1, 7} },

	/* mplsL3VpnPerfTable */
	{MPLSL3VPNVRFPERFROUTESADDED,
	 COUNTER32,
	 RONLY,
	 mplsL3vpnPerfTable,
	 5,
	 {1, 3, 1, 1, 1} },
	{MPLSL3VPNVRFPERFROUTESDELETED,
	 COUNTER32,
	 RONLY,
	 mplsL3vpnPerfTable,
	 5,
	 {1, 3, 1, 1, 2} },
	{MPLSL3VPNVRFPERFCURRNUMROUTES,
	 GAUGE32,
	 RONLY,
	 mplsL3vpnPerfTable,
	 5,
	 {1, 3, 1, 1, 3} },

	/* mplsVpnRteTable */
	{MPLSL3VPNVRFRTEINETCIDRDESTTYPE,
	 INTEGER,
	 RONLY,
	 mplsL3vpnRteTable,
	 5,
	 {1, 4, 1, 1, 1} },
	{MPLSL3VPNVRFRTEINETCIDRDEST,
	 OCTET_STRING,
	 RONLY,
	 mplsL3vpnRteTable,
	 5,
	 {1, 4, 1, 1, 2} },
	{MPLSL3VPNVRFRTEINETCIDRPFXLEN,
	 GAUGE32,
	 RONLY,
	 mplsL3vpnRteTable,
	 5,
	 {1, 4, 1, 1, 3} },
	{MPLSL3VPNVRFRTEINETCIDRPOLICY,
	 OID,
	 RONLY,
	 mplsL3vpnRteTable,
	 5,
	 {1, 4, 1, 1, 4} },
	{MPLSL3VPNVRFRTEINETCIDRNHOPTYPE,
	 INTEGER,
	 RONLY,
	 mplsL3vpnRteTable,
	 5,
	 {1, 4, 1, 1, 5} },
	{MPLSL3VPNVRFRTEINETCIDRNEXTHOP,
	 OCTET_STRING,
	 RONLY,
	 mplsL3vpnRteTable,
	 5,
	 {1, 4, 1, 1, 6} },
	{MPLSL3VPNVRFRTEINETCIDRIFINDEX,
	 INTEGER,
	 RONLY,
	 mplsL3vpnRteTable,
	 5,
	 {1, 4, 1, 1, 7} },
	{MPLSL3VPNVRFRTEINETCIDRTYPE,
	 INTEGER,
	 RONLY,
	 mplsL3vpnRteTable,
	 5,
	 {1, 4, 1, 1, 8} },
	{MPLSL3VPNVRFRTEINETCIDRPROTO,
	 INTEGER,
	 RONLY,
	 mplsL3vpnRteTable,
	 5,
	 {1, 4, 1, 1, 9} },
	{MPLSL3VPNVRFRTEINETCIDRAGE,
	 GAUGE32,
	 RONLY,
	 mplsL3vpnRteTable,
	 5,
	 {1, 4, 1, 1, 10} },
	{MPLSL3VPNVRFRTEINETCIDRNEXTHOPAS,
	 GAUGE32,
	 RONLY,
	 mplsL3vpnRteTable,
	 5,
	 {1, 4, 1, 1, 11} },
	{MPLSL3VPNVRFRTEINETCIDRMETRIC1,
	 INTEGER,
	 RONLY,
	 mplsL3vpnRteTable,
	 5,
	 {1, 4, 1, 1, 12} },
	{MPLSL3VPNVRFRTEINETCIDRMETRIC2,
	 INTEGER,
	 RONLY,
	 mplsL3vpnRteTable,
	 5,
	 {1, 4, 1, 1, 13} },
	{MPLSL3VPNVRFRTEINETCIDRMETRIC3,
	 INTEGER,
	 RONLY,
	 mplsL3vpnRteTable,
	 5,
	 {1, 4, 1, 1, 14} },
	{MPLSL3VPNVRFRTEINETCIDRMETRIC4,
	 INTEGER,
	 RONLY,
	 mplsL3vpnRteTable,
	 5,
	 {1, 4, 1, 1, 15} },
	{MPLSL3VPNVRFRTEINETCIDRMETRIC5,
	 INTEGER,
	 RONLY,
	 mplsL3vpnRteTable,
	 5,
	 {1, 4, 1, 1, 16} },
	{MPLSL3VPNVRFRTEINETCIDRXCPOINTER,
	 OCTET_STRING,
	 RONLY,
	 mplsL3vpnRteTable,
	 5,
	 {1, 4, 1, 1, 17} },
	{MPLSL3VPNVRFRTEINETCIDRSTATUS,
	 INTEGER,
	 RONLY,
	 mplsL3vpnRteTable,
	 5,
	 {1, 4, 1, 1, 18} },
};

/* timeticks are in hundredths of a second */
static void bgp_mpls_l3vpn_update_timeticks(time_t *counter)
{
	struct timeval tv;

	monotime(&tv);
	*counter = (tv.tv_sec * 100) + (tv.tv_usec / 10000);
}

static int bgp_mpls_l3vpn_update_last_changed(struct bgp *bgp)
{
	if (bgp->snmp_stats)
		bgp_mpls_l3vpn_update_timeticks(
			&(bgp->snmp_stats->modify_time));
	return 0;
}

static uint32_t bgp_mpls_l3vpn_current_routes(struct bgp *l3vpn_bgp)
{
	uint32_t count = 0;
	struct bgp_table *table;
	struct bgp_dest *dest;
	struct bgp_path_info *pi;

	table = l3vpn_bgp->rib[AFI_IP][SAFI_UNICAST];
	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest)) {
		pi = bgp_dest_get_bgp_path_info(dest);
		for (; pi; pi = pi->next)
			count++;
	}
	table = l3vpn_bgp->rib[AFI_IP6][SAFI_UNICAST];
	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest)) {
		pi = bgp_dest_get_bgp_path_info(dest);
		for (; pi; pi = pi->next)
			count++;
	}
	return count;
}

static int bgp_init_snmp_stats(struct bgp *bgp)
{
	if (is_bgp_vrf_mplsvpn(bgp)) {
		if (bgp->snmp_stats == NULL) {
			bgp->snmp_stats = XCALLOC(MTYPE_BGP_NAME,
						  sizeof(struct bgp_snmp_stats));
			/* fix up added routes */
			if (bgp->snmp_stats) {
				bgp->snmp_stats->routes_added =
					bgp_mpls_l3vpn_current_routes(bgp);
				bgp_mpls_l3vpn_update_timeticks(
					&(bgp->snmp_stats->creation_time));
			}
		}
	} else {
		if (bgp->snmp_stats) {
			XFREE(MTYPE_BGP_NAME, bgp->snmp_stats);
			bgp->snmp_stats = NULL;
		}
	}
	/* Something changed - update the timestamp */
	bgp_mpls_l3vpn_update_last_changed(bgp);
	return 0;
}

static int bgp_snmp_update_route_stats(struct bgp_dest *dest,
				       struct bgp_path_info *pi, bool added)
{
	struct bgp_table *table;

	if (dest) {
		table = bgp_dest_table(dest);
		/* only update if we have a stats block - MPLSVPN vrfs for now*/
		if (table && table->bgp && table->bgp->snmp_stats) {
			if (added)
				table->bgp->snmp_stats->routes_added++;
			else
				table->bgp->snmp_stats->routes_deleted++;
		}
	}
	return 0;
}

static bool is_bgp_vrf_active(struct bgp *bgp)
{
	struct vrf *vrf;
	struct interface *ifp;

	/* if there is one interface in the vrf which is up then it is deemed
	 *  active
	 */
	vrf = vrf_lookup_by_id(bgp->vrf_id);
	if (vrf == NULL)
		return false;
	RB_FOREACH (ifp, if_name_head, &vrf->ifaces_by_name) {
		/* if we are in a vrf skip the l3mdev */
		if (bgp->name && strncmp(ifp->name, bgp->name, VRF_NAMSIZ) == 0)
			continue;

		if (if_is_up(ifp))
			return true;
	}
	return false;
}

/* BGP Traps. */
static struct trap_object l3vpn_trap_list[] = {{5, {1, 2, 1, 1, 5} },
					       {5, {1, 2, 2, 1, 6} } };

static int bgp_vrf_check_update_active(struct bgp *bgp, struct interface *ifp)
{
	bool new_active = false;
	oid trap;
	struct index_oid trap_index[2];

	if (!is_bgp_vrf_mplsvpn(bgp) || bgp->snmp_stats == NULL
	    || !bgp_mplsvpn_notif_enable)
		return 0;
	new_active = is_bgp_vrf_active(bgp);
	if (bgp->snmp_stats->active != new_active) {
		/* add trap in here */
		bgp->snmp_stats->active = new_active;

		/* send relevent trap */
		if (bgp->snmp_stats->active)
			trap = MPLSL3VPNVRFUP;
		else
			trap = MPLSL3VPNDOWN;

		/*
		 * first index vrf_name + ifindex
		 * second index vrf_name
		 */
		trap_index[1].indexlen = strnlen(bgp->name, VRF_NAMSIZ);
		oid_copy_str(trap_index[0].indexname, bgp->name,
			     trap_index[1].indexlen);
		oid_copy_str(trap_index[1].indexname, bgp->name,
			     trap_index[1].indexlen);
		trap_index[0].indexlen =
			trap_index[1].indexlen + sizeof(ifindex_t);
		oid_copy_int(trap_index[0].indexname + trap_index[1].indexlen,
			     (int *)&(ifp->ifindex));

		smux_trap_multi_index(
			mpls_l3vpn_variables, array_size(mpls_l3vpn_variables),
			mpls_l3vpn_trap_oid, array_size(mpls_l3vpn_trap_oid),
			mpls_l3vpn_oid, sizeof(mpls_l3vpn_oid) / sizeof(oid),
			trap_index, array_size(trap_index), l3vpn_trap_list,
			array_size(l3vpn_trap_list), trap);
	}
	bgp_mpls_l3vpn_update_last_changed(bgp);
	return 0;
}

static uint8_t *mplsL3vpnConfiguredVrfs(struct variable *v, oid name[],
					size_t *length, int exact,
					size_t *var_len,
					WriteMethod **write_method)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;
	uint32_t count = 0;

	if (smux_header_generic(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		if (is_bgp_vrf_mplsvpn(bgp))
			count++;
	}
	return SNMP_INTEGER(count);
}

static uint8_t *mplsL3vpnActiveVrfs(struct variable *v, oid name[],
				    size_t *length, int exact, size_t *var_len,
				    WriteMethod **write_method)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;
	uint32_t count = 0;

	if (smux_header_generic(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		if (is_bgp_vrf_mplsvpn(bgp) && is_bgp_vrf_active(bgp))
			count++;
	}
	return SNMP_INTEGER(count);
}

static uint8_t *mplsL3vpnConnectedInterfaces(struct variable *v, oid name[],
					     size_t *length, int exact,
					     size_t *var_len,
					     WriteMethod **write_method)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;
	uint32_t count = 0;
	struct vrf *vrf;

	if (smux_header_generic(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		if (is_bgp_vrf_mplsvpn(bgp)) {
			vrf = vrf_lookup_by_name(bgp->name);
			if (vrf == NULL)
				continue;

			count += vrf_interface_count(vrf);
		}
	}

	return SNMP_INTEGER(count);
}

static int write_mplsL3vpnNotificationEnable(int action, uint8_t *var_val,
					     uint8_t var_val_type,
					     size_t var_val_len, uint8_t *statP,
					     oid *name, size_t length)
{
	uint32_t intval;

	if (var_val_type != ASN_INTEGER)
		return SNMP_ERR_WRONGTYPE;

	if (var_val_len != sizeof(long))
		return SNMP_ERR_WRONGLENGTH;

	intval = *(long *)var_val;
	bgp_mplsvpn_notif_enable = intval;
	return SNMP_ERR_NOERROR;
}

static uint8_t *mplsL3vpnNotificationEnable(struct variable *v, oid name[],
					    size_t *length, int exact,
					    size_t *var_len,
					    WriteMethod **write_method)
{
	if (smux_header_generic(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	*write_method = write_mplsL3vpnNotificationEnable;
	return SNMP_INTEGER(bgp_mplsvpn_notif_enable);
}

static uint8_t *mplsL3vpnVrfConfMaxPossRts(struct variable *v, oid name[],
					   size_t *length, int exact,
					   size_t *var_len,
					   WriteMethod **write_method)
{
	if (smux_header_generic(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	return SNMP_INTEGER(0);
}

static uint8_t *mplsL3vpnVrfConfRteMxThrshTime(struct variable *v, oid name[],
					       size_t *length, int exact,
					       size_t *var_len,
					       WriteMethod **write_method)
{
	if (smux_header_generic(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	return SNMP_INTEGER(0);
}

static uint8_t *mplsL3vpnIllLblRcvThrsh(struct variable *v, oid name[],
					size_t *length, int exact,
					size_t *var_len,
					WriteMethod **write_method)
{
	if (smux_header_generic(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	return SNMP_INTEGER(0);
}


static struct bgp *bgp_lookup_by_name_next(char *vrf_name)
{
	struct bgp *bgp, *bgp_next = NULL;
	struct listnode *node, *nnode;
	bool first = false;

	/*
	 * the vrfs are not stored alphabetically but since we are using the
	 * vrf name as an index we need the getnext function to return them
	 * in a atrict order. Thus run through and find the best next one.
	 */
	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		if (!is_bgp_vrf_mplsvpn(bgp))
			continue;
		if (strnlen(vrf_name, VRF_NAMSIZ) == 0 && bgp_next == NULL) {
			first = true;
			bgp_next = bgp;
			continue;
		}
		if (first || strncmp(bgp->name, vrf_name, VRF_NAMSIZ) > 0) {
			if (bgp_next == NULL)
				bgp_next = bgp;
			else if (strncmp(bgp->name, bgp_next->name, VRF_NAMSIZ)
				 < 0)
				bgp_next = bgp;
		}
	}
	return bgp_next;
}

/* 1.3.6.1.2.1.10.166.11.1.2.1.1.x = 14*/
#define IFCONFTAB_NAMELEN 14
static struct bgp *bgpL3vpnIfConf_lookup(struct variable *v, oid name[],
					 size_t *length, char *vrf_name,
					 ifindex_t *ifindex, int exact)
{
	struct bgp *bgp = NULL;
	size_t namelen = v ? v->namelen : IFCONFTAB_NAMELEN;
	struct interface *ifp;
	int vrf_name_len, len;

	/* too long ? */
	if (*length - namelen > (VRF_NAMSIZ + sizeof(uint32_t)))
		return NULL;
	/* do we have index info in the oid ? */
	if (*length - namelen != 0 && *length - namelen >= sizeof(uint32_t)) {
		/* copy the info from the oid */
		vrf_name_len = *length - (namelen + sizeof(ifindex_t));
		oid2string(name + namelen, vrf_name_len, vrf_name);
		oid2int(name + namelen + vrf_name_len, ifindex);
	}

	if (exact) {
		/* Check the length. */
		bgp = bgp_lookup_by_name(vrf_name);
		if (bgp && !is_bgp_vrf_mplsvpn(bgp))
			return NULL;
		if (!bgp)
			return NULL;
		ifp = if_lookup_by_index(*ifindex, bgp->vrf_id);
		if (!ifp)
			return NULL;
	} else {
		if (strnlen(vrf_name, VRF_NAMSIZ) == 0)
			bgp = bgp_lookup_by_name_next(vrf_name);
		else
			bgp = bgp_lookup_by_name(vrf_name);

		while (bgp) {
			ifp = if_vrf_lookup_by_index_next(*ifindex,
							  bgp->vrf_id);
			if (ifp) {
				vrf_name_len = strnlen(bgp->name, VRF_NAMSIZ);
				*ifindex = ifp->ifindex;
				len = vrf_name_len + sizeof(ifindex_t);
				oid_copy_str(name + namelen, bgp->name,
					     vrf_name_len);
				oid_copy_int(name + namelen + vrf_name_len,
					     ifindex);
				*length = len + namelen;

				return bgp;
			}
			*ifindex = 0;
			bgp = bgp_lookup_by_name_next(bgp->name);
		}

		return NULL;
	}
	return bgp;
}

static uint8_t *mplsL3vpnIfConfTable(struct variable *v, oid name[],
				     size_t *length, int exact, size_t *var_len,
				     WriteMethod **write_method)
{
	char vrf_name[VRF_NAMSIZ];
	ifindex_t ifindex = 0;
	struct bgp *l3vpn_bgp;

	if (smux_header_table(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	memset(vrf_name, 0, VRF_NAMSIZ);
	l3vpn_bgp = bgpL3vpnIfConf_lookup(v, name, length, vrf_name, &ifindex,
					  exact);
	if (!l3vpn_bgp)
		return NULL;

	switch (v->magic) {
	case MPLSL3VPNIFVPNCLASSIFICATION:
		return SNMP_INTEGER(2);
	case MPLSL3VPNIFCONFSTORAGETYPE:
		return SNMP_INTEGER(2);
	case MPLSL3VPNIFCONFROWSTATUS:
		return SNMP_INTEGER(1);
	}
	return NULL;
}

/* 1.3.6.1.2.1.10.166.11.1.2.2.1.x = 14*/
#define VRFTAB_NAMELEN 14

static struct bgp *bgpL3vpnVrf_lookup(struct variable *v, oid name[],
				      size_t *length, char *vrf_name, int exact)
{
	struct bgp *bgp = NULL;
	size_t namelen = v ? v->namelen : VRFTAB_NAMELEN;
	int len;

	if (*length - namelen > VRF_NAMSIZ)
		return NULL;
	oid2string(name + namelen, *length - namelen, vrf_name);
	if (exact) {
		/* Check the length. */
		bgp = bgp_lookup_by_name(vrf_name);
		if (bgp && !is_bgp_vrf_mplsvpn(bgp))
			return NULL;
	} else {
		bgp = bgp_lookup_by_name_next(vrf_name);

		if (bgp == NULL)
			return NULL;

		len = strnlen(bgp->name, VRF_NAMSIZ);
		oid_copy_str(name + namelen, bgp->name, len);
		*length = len + namelen;
	}
	return bgp;
}

static uint8_t *mplsL3vpnVrfTable(struct variable *v, oid name[],
				  size_t *length, int exact, size_t *var_len,
				  WriteMethod **write_method)
{
	char vrf_name[VRF_NAMSIZ];
	struct bgp *l3vpn_bgp;

	if (smux_header_table(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	memset(vrf_name, 0, VRF_NAMSIZ);
	l3vpn_bgp = bgpL3vpnVrf_lookup(v, name, length, vrf_name, exact);

	if (!l3vpn_bgp)
		return NULL;

	switch (v->magic) {
	case MPLSL3VPNVRFVPNID:
		*var_len = 0;
		return NULL;
	case MPLSL3VPNVRFDESC:
		*var_len = strnlen(l3vpn_bgp->name, VRF_NAMSIZ);
		return (uint8_t *)l3vpn_bgp->name;
	case MPLSL3VPNVRFRD:
		/*
		 * this is a horror show but the MIB dicates one RD per vrf
		 * and not one RD per AFI as we (FRR) have. So this little gem
		 * returns the V4 one if it's set OR the v6 one if it's set or
		 * zero-length string id neither are set
		 */
		memset(rd_buf, 0, RD_ADDRSTRLEN);
		if (CHECK_FLAG(l3vpn_bgp->vpn_policy[AFI_IP].flags,
			       BGP_VPN_POLICY_TOVPN_RD_SET))
			prefix_rd2str(&l3vpn_bgp->vpn_policy[AFI_IP].tovpn_rd,
				      rd_buf, sizeof(rd_buf),
				      bgp_get_asnotation(l3vpn_bgp));
		else if (CHECK_FLAG(l3vpn_bgp->vpn_policy[AFI_IP6].flags,
				    BGP_VPN_POLICY_TOVPN_RD_SET))
			prefix_rd2str(&l3vpn_bgp->vpn_policy[AFI_IP6].tovpn_rd,
				      rd_buf, sizeof(rd_buf),
				      bgp_get_asnotation(l3vpn_bgp));

		*var_len = strnlen(rd_buf, RD_ADDRSTRLEN);
		return (uint8_t *)rd_buf;
	case MPLSL3VPNVRFCREATIONTIME:
		return SNMP_INTEGER(
			(uint32_t)l3vpn_bgp->snmp_stats->creation_time);
	case MPLSL3VPNVRFOPERSTATUS:
		if (l3vpn_bgp->snmp_stats->active)
			return SNMP_INTEGER(1);
		else
			return SNMP_INTEGER(2);
	case MPLSL3VPNVRFACTIVEINTERFACES:
		return SNMP_INTEGER(bgp_vrf_interfaces(l3vpn_bgp, true));
	case MPLSL3VPNVRFASSOCIATEDINTERFACES:
		return SNMP_INTEGER(bgp_vrf_interfaces(l3vpn_bgp, false));
	case MPLSL3VPNVRFCONFMIDRTETHRESH:
		return SNMP_INTEGER(0);
	case MPLSL3VPNVRFCONFHIGHRTETHRSH:
		return SNMP_INTEGER(0);
	case MPLSL3VPNVRFCONFMAXROUTES:
		return SNMP_INTEGER(0);
	case MPLSL3VPNVRFCONFLASTCHANGED:
		return SNMP_INTEGER(
			(uint32_t)l3vpn_bgp->snmp_stats->modify_time);
	case MPLSL3VPNVRFCONFROWSTATUS:
		return SNMP_INTEGER(1);
	case MPLSL3VPNVRFCONFADMINSTATUS:
		return SNMP_INTEGER(1);
	case MPLSL3VPNVRFCONFSTORAGETYPE:
		return SNMP_INTEGER(2);
	}
	return NULL;
}

/* 1.3.6.1.2.1.10.166.11.1.2.3.1.x = 14*/
#define VRFRTTAB_NAMELEN 14
static struct bgp *bgpL3vpnVrfRt_lookup(struct variable *v, oid name[],
					size_t *length, char *vrf_name,
					uint32_t *rt_index, uint8_t *rt_type,
					int exact)
{
	uint32_t type_index_size;
	struct bgp *l3vpn_bgp;
	size_t namelen = v ? v->namelen : VRFRTTAB_NAMELEN;
	int vrf_name_len, len;

	/* too long ? */
	if (*length - namelen
	    > (VRF_NAMSIZ + sizeof(uint32_t)) + sizeof(uint8_t))
		return NULL;

	type_index_size = sizeof(uint32_t) + sizeof(uint8_t);
	/* do we have index info in the oid ? */
	if (*length - namelen != 0 && *length - namelen >= type_index_size) {
		/* copy the info from the oid */
		vrf_name_len = *length - (namelen + type_index_size);
		oid2string(name + namelen, vrf_name_len, vrf_name);
		oid2int(name + namelen + vrf_name_len, (int *)rt_index);
		*rt_type = name[namelen + vrf_name_len + sizeof(uint32_t)];
	}

	/* validate the RT index is in range */
	if (*rt_index > AFI_IP6)
		return NULL;

	if (exact) {
		l3vpn_bgp = bgp_lookup_by_name(vrf_name);
		if (l3vpn_bgp && !is_bgp_vrf_mplsvpn(l3vpn_bgp))
			return NULL;
		if (!l3vpn_bgp)
			return NULL;
		if ((*rt_index != AFI_IP) && (*rt_index != AFI_IP6))
			return NULL;
		/* do we have RT config */
		if (!(l3vpn_bgp->vpn_policy[*rt_index]
			      .rtlist[BGP_VPN_POLICY_DIR_FROMVPN]
		      || l3vpn_bgp->vpn_policy[*rt_index]
				 .rtlist[BGP_VPN_POLICY_DIR_TOVPN]))
			return NULL;
		return l3vpn_bgp;
	}
	if (strnlen(vrf_name, VRF_NAMSIZ) == 0)
		l3vpn_bgp = bgp_lookup_by_name_next(vrf_name);
	else
		l3vpn_bgp = bgp_lookup_by_name(vrf_name);
	while (l3vpn_bgp) {
		switch (*rt_index) {
		case 0:
			*rt_index = AFI_IP;
			break;
		case AFI_IP:
			*rt_index = AFI_IP6;
			break;
		case AFI_IP6:
			*rt_index = 0;
			continue;
		}
		if (*rt_index) {
			switch (*rt_type) {
			case 0:
				*rt_type = MPLSVPNVRFRTTYPEIMPORT;
				break;
			case MPLSVPNVRFRTTYPEIMPORT:
				*rt_type = MPLSVPNVRFRTTYPEEXPORT;
				break;
			case MPLSVPNVRFRTTYPEEXPORT:
			case MPLSVPNVRFRTTYPEBOTH:
				*rt_type = 0;
				break;
			}
			if (*rt_type) {
				bool import, export;

				import =
					(!!l3vpn_bgp->vpn_policy[*rt_index].rtlist
						   [BGP_VPN_POLICY_DIR_FROMVPN]);
				export =
					(!!l3vpn_bgp->vpn_policy[*rt_index].rtlist
						   [BGP_VPN_POLICY_DIR_TOVPN]);
				if (*rt_type == MPLSVPNVRFRTTYPEIMPORT
				    && !import)
					continue;
				if (*rt_type == MPLSVPNVRFRTTYPEEXPORT
				    && !export)
					continue;
				/* ckeck for both */
				if (*rt_type == MPLSVPNVRFRTTYPEIMPORT && import
				    && export
				    && ecommunity_cmp(
					    l3vpn_bgp->vpn_policy[*rt_index].rtlist
						    [BGP_VPN_POLICY_DIR_FROMVPN],
					    l3vpn_bgp->vpn_policy[*rt_index].rtlist
						    [BGP_VPN_POLICY_DIR_TOVPN]))
					*rt_type = MPLSVPNVRFRTTYPEBOTH;

				/* we have a match copy the oid info */
				vrf_name_len =
					strnlen(l3vpn_bgp->name, VRF_NAMSIZ);
				len = vrf_name_len + sizeof(uint32_t)
				      + sizeof(uint8_t);
				oid_copy_str(name + namelen, l3vpn_bgp->name,
					     vrf_name_len);
				oid_copy_int(name + namelen + vrf_name_len,
					     (int *)rt_index);
				name[(namelen + len) - 1] = *rt_type;
				*length = len + namelen;
				return l3vpn_bgp;
			}
			l3vpn_bgp = bgp_lookup_by_name_next(l3vpn_bgp->name);
		}
	}
	return NULL;
}

static const char *rt_type2str(uint8_t rt_type)
{
	switch (rt_type) {
	case MPLSVPNVRFRTTYPEIMPORT:
		return "import";
	case MPLSVPNVRFRTTYPEEXPORT:
		return "export";
	case MPLSVPNVRFRTTYPEBOTH:
		return "both";
	default:
		return "unknown";
	}
}
static uint8_t *mplsL3vpnVrfRtTable(struct variable *v, oid name[],
				    size_t *length, int exact, size_t *var_len,
				    WriteMethod **write_method)
{
	char vrf_name[VRF_NAMSIZ];
	struct bgp *l3vpn_bgp;
	uint32_t rt_index = 0;
	uint8_t rt_type = 0;
	char *rt_b = NULL;
	static char rt_b_str[BUFSIZ] = {};

	if (smux_header_table(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	memset(vrf_name, 0, VRF_NAMSIZ);
	l3vpn_bgp = bgpL3vpnVrfRt_lookup(v, name, length, vrf_name, &rt_index,
					 &rt_type, exact);

	if (!l3vpn_bgp)
		return NULL;

	switch (v->magic) {
	case MPLSL3VPNVRFRT:
		switch (rt_type) {
		case MPLSVPNVRFRTTYPEIMPORT:
			rt_b = ecommunity_ecom2str(
				l3vpn_bgp->vpn_policy[rt_index]
					.rtlist[BGP_VPN_POLICY_DIR_FROMVPN],
				ECOMMUNITY_FORMAT_ROUTE_MAP,
				ECOMMUNITY_ROUTE_TARGET);
			break;
		case MPLSVPNVRFRTTYPEEXPORT:
		case MPLSVPNVRFRTTYPEBOTH:
			rt_b = ecommunity_ecom2str(
				l3vpn_bgp->vpn_policy[rt_index]
					.rtlist[BGP_VPN_POLICY_DIR_TOVPN],
				ECOMMUNITY_FORMAT_ROUTE_MAP,
				ECOMMUNITY_ROUTE_TARGET);
			break;
		default:
			break;
		}
		if (rt_b) {
			*var_len = strnlen(rt_b, ECOMMUNITY_STRLEN);
			strlcpy(rt_b_str, rt_b, sizeof(rt_b_str));
			XFREE(MTYPE_ECOMMUNITY_STR, rt_b);
		} else {
			*var_len = 0;
		}
		return (uint8_t *)rt_b_str;
	case MPLSL3VPNVRFRTDESCR:
		/* since we dont have a description generate one */
		memset(rt_description, 0, VRF_NAMSIZ + RT_PREAMBLE_SIZE);
		snprintf(rt_description, VRF_NAMSIZ + RT_PREAMBLE_SIZE,
			 "RT %s for VRF %s", rt_type2str(rt_type),
			 l3vpn_bgp->name);
		*var_len =
			strnlen(rt_description, VRF_NAMSIZ + RT_PREAMBLE_SIZE);
		return (uint8_t *)rt_description;
	case MPLSL3VPNVRFRTROWSTATUS:
		return SNMP_INTEGER(1);
	case MPLSL3VPNVRFRTSTORAGETYPE:
		return SNMP_INTEGER(2);
	}
	return NULL;
}

/* 1.3.6.1.2.1.10.166.11.1.3.1.1.x = 14*/
#define PERFTAB_NAMELEN 14

static uint8_t *mplsL3vpnPerfTable(struct variable *v, oid name[],
				   size_t *length, int exact, size_t *var_len,
				   WriteMethod **write_method)
{
	char vrf_name[VRF_NAMSIZ];
	struct bgp *l3vpn_bgp;

	if (smux_header_table(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	memset(vrf_name, 0, VRF_NAMSIZ);
	l3vpn_bgp = bgpL3vpnVrf_lookup(v, name, length, vrf_name, exact);

	if (!l3vpn_bgp)
		return NULL;

	switch (v->magic) {
	case MPLSL3VPNVRFPERFROUTESADDED:
		return SNMP_INTEGER(l3vpn_bgp->snmp_stats->routes_added);
	case MPLSL3VPNVRFPERFROUTESDELETED:
		return SNMP_INTEGER(l3vpn_bgp->snmp_stats->routes_deleted);
	case MPLSL3VPNVRFPERFCURRNUMROUTES:
		return SNMP_INTEGER(bgp_mpls_l3vpn_current_routes(l3vpn_bgp));
	}
	return NULL;
}

static struct bgp_path_info *
bgp_lookup_route(struct bgp *l3vpn_bgp, struct bgp_dest **dest,
		 struct prefix *prefix, uint16_t policy, struct ipaddr *nexthop)
{
	struct bgp_path_info *pi = NULL;
	struct bgp_table *table;

	switch (prefix->family) {
	case AF_INET:
		table = l3vpn_bgp->rib[AFI_IP][SAFI_UNICAST];
		break;
	case AF_INET6:
		table = l3vpn_bgp->rib[AFI_IP6][SAFI_UNICAST];
		break;
	default:
		return NULL;
	}

	/*get the prefix */
	*dest = bgp_node_lookup(table, prefix);
	if (*dest == NULL)
		return NULL;

	/* now find the right path */
	pi = bgp_dest_get_bgp_path_info(*dest);
	for (; pi; pi = pi->next) {
		switch (nexthop->ipa_type) {
		case IPADDR_V4:
			if (nexthop->ip._v4_addr.s_addr
			    == pi->attr->nexthop.s_addr)
				return pi;
			break;
		case IPADDR_V6:
			if (memcmp(&nexthop->ip._v6_addr,
				   &pi->attr->mp_nexthop_global,
				   sizeof(struct in6_addr))
			    == 0)
				return pi;
			break;
		case IPADDR_NONE:
			return pi;
		}
	}
	return NULL;
}

static struct bgp_path_info *bgp_lookup_route_next(struct bgp **l3vpn_bgp,
						   struct bgp_dest **dest,
						   struct prefix *prefix,
						   uint16_t *policy,
						   struct ipaddr *nexthop)
{
	struct bgp_path_info *pi = NULL;
	struct bgp_table *table;
	const struct prefix *p;
	uint8_t family;

	/* First route?*/
	if (prefix->prefixlen == 0) {
		/* try V4 table */
		table = (*l3vpn_bgp)->rib[AFI_IP][SAFI_UNICAST];
		for (*dest = bgp_table_top(table); *dest;
		     *dest = bgp_route_next(*dest)) {
			pi = bgp_dest_get_bgp_path_info(*dest);
			if (pi)
				break;
		}

		if (!pi) {
			/* try V6 table */
			table = (*l3vpn_bgp)->rib[AFI_IP6][SAFI_UNICAST];
			for (*dest = bgp_table_top(table); *dest;
			     *dest = bgp_route_next(*dest)) {
				pi = bgp_dest_get_bgp_path_info(*dest);
				if (pi)
					break;
			}
		}
		return pi;
	}
	/* real next search for the entry first use exact lookup */
	pi = bgp_lookup_route(*l3vpn_bgp, dest, prefix, *policy, nexthop);

	if (pi == NULL)
		return NULL;

	p = bgp_dest_get_prefix(*dest);
	family = p->family;

	/* We have found the input path let's find the next one in the list */
	if (pi->next) {
		/* ensure OID is always higher for multipath routes by
		 * incrementing opaque policy oid
		 */
		*policy += 1;
		return pi->next;
	}

	/* No more paths in the input route so find the next route */
	for (; *l3vpn_bgp;
	     *l3vpn_bgp = bgp_lookup_by_name_next((*l3vpn_bgp)->name)) {
		*policy = 0;
		if (!*dest) {
			table = (*l3vpn_bgp)->rib[AFI_IP][SAFI_UNICAST];
			*dest = bgp_table_top(table);
			family = AF_INET;
		} else
			*dest = bgp_route_next(*dest);

		while (true) {
			for (; *dest; *dest = bgp_route_next(*dest)) {
				pi = bgp_dest_get_bgp_path_info(*dest);

				if (pi)
					return pi;
			}
			if (family == AF_INET) {
				table = (*l3vpn_bgp)
						->rib[AFI_IP6][SAFI_UNICAST];
				*dest = bgp_table_top(table);
				family = AF_INET6;
				continue;
			}
			break;
		}
	}

	return NULL;
}

static bool is_addr_type(oid id)
{
	switch (id) {
	case INETADDRESSTYPEUNKNOWN:
	case INETADDRESSTYPEIPV4:
	case INETADDRESSTYPEIPV6:
		return true;
	}
	return false;
}

/* 1.3.6.1.2.1.10.166.11.1.4.1.1.x = 14*/
#define PERFTAB_NAMELEN 14

static struct bgp_path_info *bgpL3vpnRte_lookup(struct variable *v, oid name[],
						size_t *length, char *vrf_name,
						struct bgp **l3vpn_bgp,
						struct bgp_dest **dest,
						uint16_t *policy, int exact)
{
	uint8_t i;
	uint8_t vrf_name_len = 0;
	struct bgp_path_info *pi = NULL;
	size_t namelen = v ? v->namelen : IFCONFTAB_NAMELEN;
	struct prefix prefix = {0};
	struct ipaddr nexthop = {0};
	uint8_t prefix_type;
	uint8_t nexthop_type;

	if ((uint32_t)(*length - namelen) > (VRF_NAMSIZ + 37))
		return NULL;

	if (*length - namelen != 0) {
		/* parse incoming OID */
		for (i = namelen; i < (*length); i++) {
			if (is_addr_type(name[i]))
				break;
			vrf_name_len++;
		}
		if (vrf_name_len > VRF_NAMSIZ)
			return NULL;

		oid2string(name + namelen, vrf_name_len, vrf_name);
		prefix_type = name[i++];
		switch (prefix_type) {
		case INETADDRESSTYPEUNKNOWN:
			prefix.family = AF_UNSPEC;
			break;
		case INETADDRESSTYPEIPV4:
			prefix.family = AF_INET;
			oid2in_addr(&name[i], sizeof(struct in_addr),
				    &prefix.u.prefix4);
			i += sizeof(struct in_addr);
			break;
		case INETADDRESSTYPEIPV6:
			prefix.family = AF_INET6;
			oid2in6_addr(&name[i], &prefix.u.prefix6);
			i += sizeof(struct in6_addr);
			break;
		}
		prefix.prefixlen = (uint8_t)name[i++];
		*policy |= name[i++] << 8;
		*policy |= name[i++];
		nexthop_type = name[i++];
		switch (nexthop_type) {
		case INETADDRESSTYPEUNKNOWN:
			nexthop.ipa_type = (prefix.family == AF_INET)
						   ? IPADDR_V4
						   : IPADDR_V6;
			break;
		case INETADDRESSTYPEIPV4:
			nexthop.ipa_type = IPADDR_V4;
			oid2in_addr(&name[i], sizeof(struct in_addr),
				    &nexthop.ip._v4_addr);
			/* i += sizeof(struct in_addr); */
			break;
		case INETADDRESSTYPEIPV6:
			nexthop.ipa_type = IPADDR_V6;
			oid2in6_addr(&name[i], &nexthop.ip._v6_addr);
			/* i += sizeof(struct in6_addr); */
			break;
		}
	}

	if (exact) {
		*l3vpn_bgp = bgp_lookup_by_name(vrf_name);
		if (*l3vpn_bgp && !is_bgp_vrf_mplsvpn(*l3vpn_bgp))
			return NULL;
		if (*l3vpn_bgp == NULL)
			return NULL;

		/* now lookup the route in this bgp table */
		pi = bgp_lookup_route(*l3vpn_bgp, dest, &prefix, *policy,
				      &nexthop);
	} else {
		int str_len;

		str_len = strnlen(vrf_name, VRF_NAMSIZ);
		if (str_len == 0) {
			*l3vpn_bgp = bgp_lookup_by_name_next(vrf_name);
		} else
			/* otherwise lookup the one we have */
			*l3vpn_bgp = bgp_lookup_by_name(vrf_name);

		if (*l3vpn_bgp == NULL)
			return NULL;

		pi = bgp_lookup_route_next(l3vpn_bgp, dest, &prefix, policy,
					   &nexthop);
		if (pi) {
			uint8_t vrf_name_len =
				strnlen((*l3vpn_bgp)->name, VRF_NAMSIZ);
			const struct prefix *p = bgp_dest_get_prefix(*dest);
			uint8_t oid_index;
			bool v4 = (p->family == AF_INET);
			uint8_t addr_len = v4 ? sizeof(struct in_addr)
					      : sizeof(struct in6_addr);
			struct attr *attr = pi->attr;

			/* copy the index parameters */
			oid_copy_str(&name[namelen], (*l3vpn_bgp)->name,
				     vrf_name_len);
			oid_index = namelen + vrf_name_len;
			if (v4) {
				name[oid_index++] = INETADDRESSTYPEIPV4;
				oid_copy_in_addr(&name[oid_index],
						 &p->u.prefix4);
			} else {
				name[oid_index++] = INETADDRESSTYPEIPV6;
				oid_copy_in6_addr(&name[oid_index],
						  &p->u.prefix6);
			}

			oid_index += addr_len;
			name[oid_index++] = p->prefixlen;
			name[oid_index++] = *policy >> 8;
			name[oid_index++] = *policy & 0xff;

			if (!BGP_ATTR_NEXTHOP_AFI_IP6(attr)) {
				if (attr->nexthop.s_addr == INADDR_ANY)
					name[oid_index++] =
						INETADDRESSTYPEUNKNOWN;
				else {
					name[oid_index++] = INETADDRESSTYPEIPV4;
					oid_copy_in_addr(&name[oid_index],
							 &attr->nexthop);
					oid_index += sizeof(struct in_addr);
				}
			} else {
				if (IN6_IS_ADDR_UNSPECIFIED(
					    &attr->mp_nexthop_global))
					name[oid_index++] =
						INETADDRESSTYPEUNKNOWN;
				else {
					name[oid_index++] = INETADDRESSTYPEIPV6;
					oid_copy_in6_addr(
						&name[oid_index],
						&attr->mp_nexthop_global);
					oid_index += sizeof(struct in6_addr);
				}
			}
			*length = oid_index;
		}
	}
	return pi;
}

static uint8_t *mplsL3vpnRteTable(struct variable *v, oid name[],
				  size_t *length, int exact, size_t *var_len,
				  WriteMethod **write_method)
{
	char vrf_name[VRF_NAMSIZ];
	struct bgp *l3vpn_bgp;
	struct bgp_dest *dest;
	struct bgp_path_info *pi, *bpi_ultimate;
	const struct prefix *p;
	uint16_t policy = 0;

	if (smux_header_table(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	memset(vrf_name, 0, VRF_NAMSIZ);
	pi = bgpL3vpnRte_lookup(v, name, length, vrf_name, &l3vpn_bgp, &dest,
				&policy, exact);


	if (!pi)
		return NULL;

	bpi_ultimate = bgp_get_imported_bpi_ultimate(pi);

	p = bgp_dest_get_prefix(dest);

	if (!p)
		return NULL;

	switch (v->magic) {
	case MPLSL3VPNVRFRTEINETCIDRDESTTYPE:
		switch (p->family) {
		case AF_INET:
			return SNMP_INTEGER(INETADDRESSTYPEIPV4);
		case AF_INET6:
			return SNMP_INTEGER(INETADDRESSTYPEIPV6);
		default:
			return SNMP_INTEGER(INETADDRESSTYPEUNKNOWN);
		}
	case MPLSL3VPNVRFRTEINETCIDRDEST:
		switch (p->family) {
		case AF_INET:
			return SNMP_IPADDRESS(p->u.prefix4);
		case AF_INET6:
			return SNMP_IP6ADDRESS(p->u.prefix6);
		default:
			*var_len = 0;
			return NULL;
		}
	case MPLSL3VPNVRFRTEINETCIDRPFXLEN:
		return SNMP_INTEGER(p->prefixlen);
	case MPLSL3VPNVRFRTEINETCIDRPOLICY:
		*var_len = sizeof(mpls_l3vpn_policy_oid);
		mpls_l3vpn_policy_oid[0] = policy >> 8;
		mpls_l3vpn_policy_oid[1] = policy & 0xff;
		return (uint8_t *)mpls_l3vpn_policy_oid;
	case MPLSL3VPNVRFRTEINETCIDRNHOPTYPE:
		if (!BGP_ATTR_NEXTHOP_AFI_IP6(pi->attr)) {
			if (pi->attr->nexthop.s_addr == INADDR_ANY)
				return SNMP_INTEGER(INETADDRESSTYPEUNKNOWN);
			else
				return SNMP_INTEGER(INETADDRESSTYPEIPV4);
		} else if (IN6_IS_ADDR_UNSPECIFIED(
				   &pi->attr->mp_nexthop_global))
			return SNMP_INTEGER(INETADDRESSTYPEUNKNOWN);
		else
			return SNMP_INTEGER(INETADDRESSTYPEIPV6);

	case MPLSL3VPNVRFRTEINETCIDRNEXTHOP:
		if (!BGP_ATTR_NEXTHOP_AFI_IP6(pi->attr))
			if (pi->attr->nexthop.s_addr == INADDR_ANY) {
				*var_len = 0;
				return (uint8_t *)empty_nhop;
			} else
				return SNMP_IPADDRESS(pi->attr->nexthop);
		else if (IN6_IS_ADDR_UNSPECIFIED(
				 &pi->attr->mp_nexthop_global)) {
			*var_len = 0;
			return (uint8_t *)empty_nhop;
		} else
			return SNMP_IP6ADDRESS(pi->attr->mp_nexthop_global);

	case MPLSL3VPNVRFRTEINETCIDRIFINDEX:
		if (pi->nexthop && pi->nexthop->nexthop)
			return SNMP_INTEGER(pi->nexthop->nexthop->ifindex);
		else
			return SNMP_INTEGER(0);
	case MPLSL3VPNVRFRTEINETCIDRTYPE:
		if (pi->nexthop && pi->nexthop->nexthop) {
			switch (pi->nexthop->nexthop->type) {
			case NEXTHOP_TYPE_IFINDEX:
				return SNMP_INTEGER(
					MPLSL3VPNVRFRTECIDRTYPELOCAL);
			case NEXTHOP_TYPE_IPV4:
			case NEXTHOP_TYPE_IPV4_IFINDEX:
			case NEXTHOP_TYPE_IPV6:
			case NEXTHOP_TYPE_IPV6_IFINDEX:
				return SNMP_INTEGER(
					MPLSL3VPNVRFRTECIDRTYPEREMOTE);
			case NEXTHOP_TYPE_BLACKHOLE:
				switch (pi->nexthop->nexthop->bh_type) {
				case BLACKHOLE_REJECT:
					return SNMP_INTEGER(
						MPLSL3VPNVRFRTECIDRTYPEREJECT);
				case BLACKHOLE_UNSPEC:
				case BLACKHOLE_NULL:
				case BLACKHOLE_ADMINPROHIB:
					return SNMP_INTEGER(
						MPLSL3VPNVRFRTECIDRTYPEBLACKHOLE);
				}
				break;
			}
		} else
			return SNMP_INTEGER(MPLSL3VPNVRFRTECIDRTYPEOTHER);
		break;
	case MPLSL3VPNVRFRTEINETCIDRPROTO:
		switch (pi->type) {
		case ZEBRA_ROUTE_CONNECT:
			return SNMP_INTEGER(IANAIPROUTEPROTOCOLLOCAL);
		case ZEBRA_ROUTE_STATIC:
			return SNMP_INTEGER(IANAIPROUTEPROTOCOLNETMGMT);
		case ZEBRA_ROUTE_RIP:
		case ZEBRA_ROUTE_RIPNG:
			return SNMP_INTEGER(IANAIPROUTEPROTOCOLRIP);
		case ZEBRA_ROUTE_OSPF:
		case ZEBRA_ROUTE_OSPF6:
			return SNMP_INTEGER(IANAIPROUTEPROTOCOLOSPF);
		case ZEBRA_ROUTE_ISIS:
			return SNMP_INTEGER(IANAIPROUTEPROTOCOLISIS);
		case ZEBRA_ROUTE_BGP:
			return SNMP_INTEGER(IANAIPROUTEPROTOCOLBGP);
		case ZEBRA_ROUTE_EIGRP:
			return SNMP_INTEGER(IANAIPROUTEPROTOCOLCISCOEIGRP);
		default:
			return SNMP_INTEGER(IANAIPROUTEPROTOCOLOTHER);
		}
	case MPLSL3VPNVRFRTEINETCIDRAGE:
		return SNMP_INTEGER(pi->uptime);
	case MPLSL3VPNVRFRTEINETCIDRNEXTHOPAS:
		return SNMP_INTEGER(pi->peer ? pi->peer->as : 0);
	case MPLSL3VPNVRFRTEINETCIDRMETRIC1:
		if (bpi_ultimate->extra)
			return SNMP_INTEGER(bpi_ultimate->extra->igpmetric);
		else
			return SNMP_INTEGER(0);
	case MPLSL3VPNVRFRTEINETCIDRMETRIC2:
		return SNMP_INTEGER(-1);
	case MPLSL3VPNVRFRTEINETCIDRMETRIC3:
		return SNMP_INTEGER(-1);
	case MPLSL3VPNVRFRTEINETCIDRMETRIC4:
		return SNMP_INTEGER(-1);
	case MPLSL3VPNVRFRTEINETCIDRMETRIC5:
		return SNMP_INTEGER(-1);
	case MPLSL3VPNVRFRTEINETCIDRXCPOINTER:
		return SNMP_OCTET(0);
	case MPLSL3VPNVRFRTEINETCIDRSTATUS:
		return SNMP_INTEGER(1);
	}
	return NULL;
}

void bgp_mpls_l3vpn_module_init(void)
{
	hook_register(bgp_vrf_status_changed, bgp_vrf_check_update_active);
	hook_register(bgp_snmp_init_stats, bgp_init_snmp_stats);
	hook_register(bgp_snmp_update_last_changed,
		      bgp_mpls_l3vpn_update_last_changed);
	hook_register(bgp_snmp_update_stats, bgp_snmp_update_route_stats);
	REGISTER_MIB("mplsL3VpnMIB", mpls_l3vpn_variables, variable,
		     mpls_l3vpn_oid);
}
