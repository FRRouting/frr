/* MPLS/BGP L3VPN MIB
 * Copyright (C) 2020 Volta Networks Inc
 *
 * This file is part of FRR.
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

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include "if.h"
#include "log.h"
#include "prefix.h"
#include "command.h"
#include "thread.h"
#include "smux.h"
#include "filter.h"
#include "hook.h"
#include "libfrr.h"
#include "version.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_mplsvpn_snmp.h"

#define BGP_mplsvpn_notif_enable_true 1
#define BGP_mplsvpn_notif_enable_false 2

static uint8_t bgp_mplsvpn_notif_enable = SNMP_FALSE;

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

/* SNMP value hack. */
#define INTEGER ASN_INTEGER
#define INTEGER32 ASN_INTEGER
#define COUNTER32 ASN_COUNTER
#define OCTET_STRING ASN_OCTET_STR
#define IPADDRESS ASN_IPADDRESS
#define GAUGE32 ASN_UNSIGNED

/* Declare static local variables for convenience. */
SNMP_LOCAL_VARIABLES

/* BGP-MPLS-MIB innstances */
static oid mpls_l3vpn_oid[] = {MPLSL3VPNMIB};

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

};

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

	zlog_debug("PJDR: %s", __func__);
	if (var_val_type != ASN_INTEGER) {
		return SNMP_ERR_WRONGTYPE;
	}

	if (var_val_len != sizeof(long)) {
		return SNMP_ERR_WRONGLENGTH;
	}

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

	zlog_debug("PJDR: %s", __func__);
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


void bgp_mpls_l3vpn_module_init(void)
{
	REGISTER_MIB("mplsL3VpnMIB", mpls_l3vpn_variables, variable,
		     mpls_l3vpn_oid);
}
