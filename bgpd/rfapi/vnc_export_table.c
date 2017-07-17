/*
 *
 * Copyright 2009-2016, LabN Consulting, L.L.C.
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */


#include "lib/zebra.h"
#include "lib/prefix.h"
#include "lib/table.h"
#include "lib/memory.h"
#include "lib/vty.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"

#include "bgpd/rfapi/vnc_export_table.h"
#include "bgpd/rfapi/rfapi_private.h"
#include "bgpd/rfapi/rfapi_import.h"
#include "bgpd/rfapi/vnc_debug.h"

struct route_node *vnc_etn_get(struct bgp *bgp, vnc_export_type_t type,
			       struct prefix *p)
{
	struct route_table *t = NULL;
	struct route_node *rn = NULL;
	afi_t afi;

	if (!bgp || !bgp->rfapi)
		return NULL;

	afi = family2afi(p->family);
	assert(afi == AFI_IP || afi == AFI_IP6);

	switch (type) {
	case EXPORT_TYPE_BGP:
		if (!bgp->rfapi->rt_export_bgp[afi])
			bgp->rfapi->rt_export_bgp[afi] = route_table_init();
		t = bgp->rfapi->rt_export_bgp[afi];
		break;

	case EXPORT_TYPE_ZEBRA:
		if (!bgp->rfapi->rt_export_zebra[afi])
			bgp->rfapi->rt_export_zebra[afi] = route_table_init();
		t = bgp->rfapi->rt_export_zebra[afi];
		break;
	}

	if (t)
		rn = route_node_get(t, p);
	return rn;
}

struct route_node *vnc_etn_lookup(struct bgp *bgp, vnc_export_type_t type,
				  struct prefix *p)
{
	struct route_table *t = NULL;
	struct route_node *rn = NULL;
	afi_t afi;

	if (!bgp || !bgp->rfapi)
		return NULL;

	afi = family2afi(p->family);
	assert(afi == AFI_IP || afi == AFI_IP6);

	switch (type) {
	case EXPORT_TYPE_BGP:
		if (!bgp->rfapi->rt_export_bgp[afi])
			bgp->rfapi->rt_export_bgp[afi] = route_table_init();
		t = bgp->rfapi->rt_export_bgp[afi];
		break;

	case EXPORT_TYPE_ZEBRA:
		if (!bgp->rfapi->rt_export_zebra[afi])
			bgp->rfapi->rt_export_zebra[afi] = route_table_init();
		t = bgp->rfapi->rt_export_zebra[afi];
		break;
	}

	if (t)
		rn = route_node_lookup(t, p);
	return rn;
}

struct vnc_export_info *vnc_eti_get(struct bgp *bgp, vnc_export_type_t etype,
				    struct prefix *p, struct peer *peer,
				    uint8_t type, uint8_t subtype)
{
	struct route_node *etn;
	struct vnc_export_info *eti;

	etn = vnc_etn_get(bgp, etype, p);
	assert(etn);

	for (eti = etn->info; eti; eti = eti->next) {
		if (peer == eti->peer && type == eti->type
		    && subtype == eti->subtype) {

			break;
		}
	}

	if (eti) {
		route_unlock_node(etn);
	} else {
		eti = XCALLOC(MTYPE_RFAPI_ETI, sizeof(struct vnc_export_info));
		assert(eti);
		eti->node = etn;
		eti->peer = peer;
		peer_lock(peer);
		eti->type = type;
		eti->subtype = subtype;
		eti->next = etn->info;
		etn->info = eti;
	}

	return eti;
}

void vnc_eti_delete(struct vnc_export_info *goner)
{
	struct route_node *etn;
	struct vnc_export_info *eti;
	struct vnc_export_info *eti_prev = NULL;

	etn = goner->node;

	for (eti = etn->info; eti; eti_prev = eti, eti = eti->next) {
		if (eti == goner)
			break;
	}

	if (!eti) {
		vnc_zlog_debug_verbose("%s: COULDN'T FIND ETI", __func__);
		return;
	}

	if (eti_prev) {
		eti_prev->next = goner->next;
	} else {
		etn->info = goner->next;
	}

	peer_unlock(eti->peer);
	goner->node = NULL;
	XFREE(MTYPE_RFAPI_ETI, goner);

	route_unlock_node(etn);
}

struct vnc_export_info *vnc_eti_checktimer(struct bgp *bgp,
					   vnc_export_type_t etype,
					   struct prefix *p, struct peer *peer,
					   uint8_t type, uint8_t subtype)
{
	struct route_node *etn;
	struct vnc_export_info *eti;

	etn = vnc_etn_lookup(bgp, etype, p);
	if (!etn)
		return NULL;

	for (eti = etn->info; eti; eti = eti->next) {
		if (peer == eti->peer && type == eti->type
		    && subtype == eti->subtype) {

			break;
		}
	}

	route_unlock_node(etn);

	if (eti && eti->timer)
		return eti;

	return NULL;
}
