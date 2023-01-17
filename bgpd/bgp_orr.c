/*
 * BGP Optimal Route Reflection
 * Copyright (C) 2021  Samsung R&D Institute India - Bangalore.
 *			Madhurilatha Kuruganti
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>
#include "bgpd/bgpd.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_orr.h"
#include "bgpd/bgp_vty.h"
#include "zclient.h"

DEFINE_MTYPE_STATIC(BGPD, ORR_IGP_INFO, "ORR IGP Metric info");

static inline bool is_orr_primary_root(struct bgp_orr_group *orr_group,
				       char *host)
{
	return orr_group->primary && strmatch(orr_group->primary->host, host);
}

static inline bool is_orr_secondary_root(struct bgp_orr_group *orr_group,
					 char *host)
{
	return orr_group->secondary &&
	       strmatch(orr_group->secondary->host, host);
}

static inline bool is_orr_tertiary_root(struct bgp_orr_group *orr_group,
					char *host)
{
	return orr_group->tertiary && strmatch(orr_group->tertiary->host, host);
}

static inline bool is_orr_active_root(struct bgp_orr_group *orr_group,
				      char *host)
{
	return orr_group->active && strmatch(orr_group->active->host, host);
}

static inline bool is_orr_root_node(struct bgp_orr_group *orr_group, char *host)
{
	return is_orr_primary_root(orr_group, host) ||
	       is_orr_secondary_root(orr_group, host) ||
	       is_orr_tertiary_root(orr_group, host);
}

static inline bool is_peer_orr_group_member(struct peer *peer, afi_t afi,
					    safi_t safi, const char *name)
{
	return peer_af_flag_check(peer, afi, safi, PEER_FLAG_ORR_GROUP) &&
	       strmatch(peer->orr_group_name[afi][safi], name);
}

static inline bool is_peer_reachable(struct peer *peer, afi_t afi, safi_t safi)
{
	return peer && peer->afc_nego[afi][safi] && peer_established(peer);
}

static inline bool is_peer_active_eligible(struct peer *peer, afi_t afi,
					   safi_t safi, const char *name)
{
	return is_peer_reachable(peer, afi, safi) &&
	       is_peer_orr_group_member(peer, afi, safi, name);
}

static void bgp_orr_igp_metric_register(struct bgp_orr_group *orr_group,
					bool reg);

static void
bgp_peer_update_orr_group_active_root(struct peer *peer, afi_t afi, safi_t safi,
				      struct bgp_orr_group *orr_group);

static struct bgp_orr_group *bgp_orr_group_new(struct bgp *bgp, afi_t afi,
					       safi_t safi, const char *name)
{
	int ret;
	struct list *orr_group_list = NULL;
	struct bgp_orr_group *orr_group = NULL;

	assert(bgp && name);

	if (!bgp->orr_group[afi][safi])
		bgp->orr_group[afi][safi] = list_new();

	orr_group_list = bgp->orr_group[afi][safi];
	orr_group = XCALLOC(MTYPE_BGP_ORR_GROUP, sizeof(struct bgp_orr_group));

	listnode_add(orr_group_list, orr_group);

	orr_group->name = XSTRDUP(MTYPE_BGP_ORR_GROUP_NAME, name);
	orr_group->afi = afi;
	orr_group->safi = safi;
	orr_group->primary = orr_group->secondary = orr_group->tertiary = NULL;
	orr_group->bgp = bgp;

	/* Initialize ORR Group route table */
	orr_group->route_table = bgp_table_init(bgp, afi, safi);
	assert(orr_group->route_table);

	/*
	 * Register for opaque messages from IGPs when first ORR group is
	 * configured.
	 */
	if (!bgp->orr_group_count) {
		ret = zclient_register_opaque(zclient, ORR_IGP_METRIC_UPDATE);
		if (ret != ZCLIENT_SEND_SUCCESS)
			bgp_orr_debug(
				"%s: zclient_register_opaque failed with ret = %d",
				__func__, ret);
	}

	bgp->orr_group_count++;

	return orr_group;
}

static void bgp_orr_group_free(struct bgp_orr_group *orr_group)
{
	afi_t afi;
	safi_t safi;
	struct bgp *bgp;

	assert(orr_group && orr_group->bgp && orr_group->name);

	bgp_orr_debug("%s: Deleting ORR group %s", __func__, orr_group->name);

	afi = orr_group->afi;
	safi = orr_group->safi;
	bgp = orr_group->bgp;

	/*
	 * Unregister with IGP for metric calculation from specified location
	 * and delete igp_metric_info calculated for this group
	 */
	bgp_orr_igp_metric_register(orr_group, false);

	/* Free RR client list associated with this ORR group */
	if (orr_group->rr_client_list)
		list_delete(&orr_group->rr_client_list);

	/* Free route table */
	bgp_table_unlock(orr_group->route_table);
	orr_group->route_table = NULL;

	/* Unset ORR Group parameters */
	XFREE(MTYPE_BGP_ORR_GROUP_NAME, orr_group->name);

	listnode_delete(bgp->orr_group[afi][safi], orr_group);
	XFREE(MTYPE_BGP_ORR_GROUP, orr_group);

	bgp->orr_group_count--;

	if (!bgp->orr_group[afi][safi]->count)
		list_delete(&bgp->orr_group[afi][safi]);
}

struct bgp_orr_group *bgp_orr_group_lookup_by_name(struct bgp *bgp, afi_t afi,
						   safi_t safi,
						   const char *name)
{
	struct list *orr_group_list = NULL;
	struct bgp_orr_group *group = NULL;
	struct listnode *node;

	assert(bgp);

	orr_group_list = bgp->orr_group[afi][safi];
	if (!orr_group_list)
		return NULL;

	for (ALL_LIST_ELEMENTS_RO(orr_group_list, node, group))
		if (strmatch(group->name, name))
			return group;

	bgp_orr_debug("%s: For %s, ORR Group '%s' not found.", __func__,
		      get_afi_safi_str(afi, safi, false), name);

	return NULL;
}

static char *bgp_orr_group_rrclient_lookup(struct bgp_orr_group *orr_group,
					   const char *rr_client_host)
{
	char *rrclient = NULL;
	struct list *orr_group_rrclient_list = NULL;
	struct listnode *node;

	orr_group_rrclient_list = orr_group->rr_client_list;
	if (!orr_group_rrclient_list)
		return NULL;

	for (ALL_LIST_ELEMENTS_RO(orr_group_rrclient_list, node, rrclient))
		if (strmatch(rrclient, rr_client_host))
			return rrclient;

	bgp_orr_debug(
		"%s: For %s, %s not found in ORR Group '%s' RR Client list",
		__func__,
		get_afi_safi_str(orr_group->afi, orr_group->safi, false),
		rr_client_host, orr_group->name);

	return NULL;
}

static void bgp_orr_group_rrclient_update(struct peer *peer, afi_t afi,
					  safi_t safi,
					  const char *orr_group_name, bool add)
{
	char *rr_client = NULL;
	struct bgp_orr_group *orr_group = NULL;
	struct list *rr_client_list = NULL;

	assert(peer && peer->bgp && orr_group_name);

	/* Get BGP ORR entry for the given address-family */
	orr_group = bgp_orr_group_lookup_by_name(peer->bgp, afi, safi,
						 orr_group_name);
	if (!orr_group) {
		bgp_orr_debug("%s: For %s, ORR Group '%s' not found.", __func__,
			      get_afi_safi_str(afi, safi, false),
			      orr_group_name);
		return;
	}

	/* Get BGP ORR client entry for the given RR client */
	rr_client = bgp_orr_group_rrclient_lookup(orr_group, peer->host);

	/* Nothing to do */
	if ((rr_client && add) || (!rr_client && !add))
		return;

	if (add) {
		/* Create BGP ORR RR client entry to the ORR Group */
		if (!orr_group->rr_client_list)
			orr_group->rr_client_list = list_new();
		rr_client_list = orr_group->rr_client_list;
		rr_client = XSTRDUP(MTYPE_BGP_PEER_HOST, peer->host);

		listnode_add(rr_client_list, rr_client);

		bgp_orr_debug(
			"%s: For %s, %pBP is added to ORR Group '%s' RR Client list.",
			__func__, get_afi_safi_str(afi, safi, false), peer,
			orr_group_name);
	} else {
		/* Delete BGP ORR RR client entry from the ORR Group */
		listnode_delete(orr_group->rr_client_list, rr_client);
		XFREE(MTYPE_BGP_PEER_HOST, rr_client);
		if (!orr_group->rr_client_list->count)
			list_delete(&orr_group->rr_client_list);

		bgp_orr_debug(
			"%s: For %s, %pBP is removed from ORR Group '%s' RR Client list.",
			__func__, get_afi_safi_str(afi, safi, false), peer,
			orr_group_name);
	}
}

/* Create/Update BGP Optimal Route Reflection Group */
int bgp_afi_safi_orr_group_set(struct bgp *bgp, afi_t afi, safi_t safi,
			       const char *name, struct peer *primary,
			       struct peer *secondary, struct peer *tertiary)
{
	bool primary_eligible = false;
	bool secondary_eligible = false;
	bool tertiary_eligible = false;
	struct bgp_orr_group *orr_group = NULL;

	bgp_orr_debug(
		"%s: For %s, ORR Group '%s' Primary %pBP Secondary %pBP Tertiary %pBP",
		__func__, get_afi_safi_str(afi, safi, false), name, primary,
		secondary, tertiary);

	/* Get BGP ORR entry for the given address-family */
	orr_group = bgp_orr_group_lookup_by_name(bgp, afi, safi, name);
	if (!orr_group) {
		/* Create BGP ORR entry for the given address-family */
		orr_group = bgp_orr_group_new(bgp, afi, safi, name);
	}

	/* Compare and update Primary Root Address */
	if (primary) {
		if (!orr_group->primary ||
		    !strmatch(orr_group->primary->host, primary->host))
			orr_group->primary = primary;
		else
			bgp_orr_debug("%s: No change in Primary Root",
				      __func__);

		/*
		 * Update Active Root if there is a change and primary is
		 * reachable.
		 */
		primary_eligible =
			is_peer_active_eligible(primary, afi, safi, name);
		if (!orr_group->active) {
			orr_group->active = primary;
			bgp_orr_igp_metric_register(orr_group, true);
		} else if (orr_group->primary &&
			   !strmatch(orr_group->active->host,
				     orr_group->primary->host)) {
			bgp_orr_igp_metric_register(orr_group, false);
			orr_group->active = primary;
			bgp_orr_igp_metric_register(orr_group, true);
		} else
			bgp_orr_debug("%s: %s", __func__,
				      orr_group->primary
					      ? "No change in Active Root"
					      : "Primary Root is NULL");
	} else {
		if (orr_group->primary) {
			if (orr_group->active &&
			    strmatch(orr_group->active->host,
				     orr_group->primary->host)) {
				bgp_orr_igp_metric_register(orr_group, false);

				orr_group->active = NULL;
			}
			orr_group->primary = NULL;
		}
	}

	/* Compare and update Secondary Root Address */
	if (secondary) {
		if (!orr_group->secondary ||
		    !strmatch(orr_group->secondary->host, secondary->host))
			orr_group->secondary = secondary;
		else
			bgp_orr_debug("%s: No change in Secondary Root",
				      __func__);

		/* Update Active Root if Primary is not reachable */
		secondary_eligible =
			is_peer_active_eligible(secondary, afi, safi, name);
		if (!orr_group->active) {
			orr_group->active = secondary;
			bgp_orr_igp_metric_register(orr_group, true);
		} else if (!primary_eligible && orr_group->secondary &&
			   !strmatch(orr_group->active->host,
				     orr_group->secondary->host)) {
			bgp_orr_igp_metric_register(orr_group, false);
			orr_group->active = secondary;
			bgp_orr_igp_metric_register(orr_group, true);
		} else
			bgp_orr_debug(
				"%s: %s", __func__,
				primary_eligible
					? "Primary is Active Root"
					: orr_group->secondary
						  ? "No change in Active Root"
						  : "Secondary Root is NULL");
	} else {
		if (orr_group->secondary) {
			if (orr_group->active &&
			    strmatch(orr_group->active->host,
				     orr_group->secondary->host)) {
				bgp_orr_igp_metric_register(orr_group, false);

				orr_group->active = NULL;
			}
			orr_group->secondary = NULL;
		}
	}

	/* Compare and update Tertiary Root Address */
	if (tertiary) {
		if (!orr_group->tertiary ||
		    !strmatch(orr_group->tertiary->host, tertiary->host))
			orr_group->tertiary = tertiary;
		else
			bgp_orr_debug("%s: No change in Tertiay Root",
				      __func__);

		/*
		 * Update Active Root if Primary & Secondary are not reachable
		 */
		tertiary_eligible =
			is_peer_active_eligible(tertiary, afi, safi, name);
		if (!orr_group->active) {
			orr_group->active = tertiary;
			bgp_orr_igp_metric_register(orr_group, true);
		} else if (!primary_eligible && !secondary_eligible &&
			   orr_group->tertiary &&
			   !strmatch(orr_group->active->host,
				     orr_group->tertiary->host)) {
			bgp_orr_igp_metric_register(orr_group, false);

			orr_group->active = tertiary;
			bgp_orr_igp_metric_register(orr_group, true);
		} else
			bgp_orr_debug(
				"%s: %s", __func__,
				primary_eligible
					? "Primary is Active Root"
					: secondary_eligible
						  ? "Secondary is Active Root"
						  : !orr_group->tertiary
							    ? "Tertiary Root is NULL"
							    : "No change in Active Root");
	} else {
		if (orr_group->tertiary) {
			if (orr_group->active &&
			    strmatch(orr_group->active->host,
				     orr_group->tertiary->host)) {
				bgp_orr_igp_metric_register(orr_group, false);

				orr_group->active = NULL;
			}
			orr_group->tertiary = NULL;
		}
	}

	if (orr_group->active && !primary_eligible && !secondary_eligible &&
	    !tertiary_eligible) {
		bgp_orr_igp_metric_register(orr_group, false);

		orr_group->active = NULL;
	}

	bgp_orr_debug("%s: For %s, ORR Group '%s' Active Root is %pBP",
		      __func__, get_afi_safi_str(afi, safi, false), name,
		      orr_group->active);

	return CMD_SUCCESS;
}

/* Delete BGP Optimal Route Reflection Group */
int bgp_afi_safi_orr_group_unset(struct bgp *bgp, afi_t afi, safi_t safi,
				 const char *name)
{
	struct bgp_orr_group *orr_group;

	orr_group = bgp_orr_group_lookup_by_name(bgp, afi, safi, name);
	if (!orr_group)
		return CMD_WARNING;

	/* Check if there are any neighbors configured with this ORR Group */
	if (orr_group->rr_client_list) {
		bgp_orr_debug(
			"%s: For %s, ORR Group '%s' not removed as '%s' is configured on neighbor(s)",
			__func__,
			get_afi_safi_str(orr_group->afi, orr_group->safi,
					 false),
			name, name);
		return CMD_WARNING;
	}

	bgp_orr_group_free(orr_group);
	return CMD_SUCCESS;
}

/* Set optimal route reflection group to the peer */
static int peer_orr_group_set(struct peer *peer, afi_t afi, safi_t safi,
			      const char *orr_group_name)
{
	struct bgp_orr_group *orr_group = NULL;

	if (!peer)
		return CMD_WARNING;

	/* Get BGP ORR entry for the given address-family */
	orr_group = bgp_orr_group_lookup_by_name(peer->bgp, afi, safi,
						 orr_group_name);
	if (!orr_group) {
		/* Create BGP ORR entry for the given address-family */
		orr_group =
			bgp_orr_group_new(peer->bgp, afi, safi, orr_group_name);
	}

	/* Skip processing if there is no change in ORR Group */
	if (peer_af_flag_check(peer, afi, safi, PEER_FLAG_ORR_GROUP)) {
		if (strmatch(peer->orr_group_name[afi][safi], orr_group_name)) {
			bgp_orr_debug(
				"%s: For %s, ORR Group '%s' is already configured on %pBP",
				__func__, get_afi_safi_str(afi, safi, false),
				orr_group_name, peer);
			return CMD_SUCCESS;
		}
		/* Remove the peer from ORR Group's peer list */
		bgp_orr_group_rrclient_update(peer, afi, safi,
					      peer->orr_group_name[afi][safi],
					      false);
		XFREE(MTYPE_BGP_ORR_GROUP_NAME,
		      peer->orr_group_name[afi][safi]);
	}

	peer->orr_group_name[afi][safi] =
		XSTRDUP(MTYPE_BGP_ORR_GROUP_NAME, orr_group_name);
	SET_FLAG(peer->af_flags[afi][safi], PEER_FLAG_ORR_GROUP);

	/* Add the peer to ORR Group's client list */
	bgp_orr_group_rrclient_update(peer, afi, safi, orr_group_name, true);

	/* Update ORR group active root and register with IGP */
	bgp_peer_update_orr_group_active_root(peer, afi, safi, orr_group);

	return CMD_SUCCESS;
}

/* Unset optimal route reflection group from the peer*/
int peer_orr_group_unset(struct peer *peer, afi_t afi, safi_t safi,
			 const char *orr_group_name)
{
	struct bgp_orr_group *orr_group = NULL;

	assert(peer && peer->bgp && orr_group_name);

	if (!peer_af_flag_check(peer, afi, safi, PEER_FLAG_ORR_GROUP) ||
	    !strmatch(peer->orr_group_name[afi][safi], orr_group_name)) {
		bgp_orr_debug(
			"%s: For %s, ORR Group '%s' is not configured on %pBP",
			__func__, get_afi_safi_str(afi, safi, false),
			orr_group_name, peer);
		return CMD_ERR_NO_MATCH;
	}

	/* Check if this RR Client is one of the root nodes */
	orr_group = bgp_orr_group_lookup_by_name(peer->bgp, afi, safi,
						 orr_group_name);

	/* Should not be Null when orr-group is enabled on peer */
	assert(orr_group);

	/* Check if the peer is one of the root nodes of the ORR group */
	if (is_orr_root_node(orr_group, peer->host))
		return CMD_WARNING;

	/* Remove the peer from ORR Group's client list */
	bgp_orr_group_rrclient_update(peer, afi, safi, orr_group_name, false);

	/* Update ORR group active root and unregister with IGP */
	bgp_peer_update_orr_group_active_root(peer, afi, safi, orr_group);

	UNSET_FLAG(peer->af_flags[afi][safi], PEER_FLAG_ORR_GROUP);
	XFREE(MTYPE_BGP_ORR_GROUP_NAME, peer->orr_group_name[afi][safi]);

	return CMD_SUCCESS;
}

int bgp_afi_safi_orr_group_set_vty(struct vty *vty, afi_t afi, safi_t safi,
				   const char *name, const char *primary_str,
				   const char *secondary_str,
				   const char *tertiary_str, bool set)
{
	int ret = CMD_WARNING_CONFIG_FAILED;
	struct bgp *bgp;
	struct peer *primary = NULL, *secondary = NULL, *tertiary = NULL;

	bgp = bgp_get_default();
	if (!bgp) {
		vty_out(vty, "%% No BGP process is configured\n");
		return ret;
	}

	if (!set) {
		ret = bgp_afi_safi_orr_group_unset(bgp, afi, safi, name);
		if (ret != CMD_SUCCESS)
			vty_out(vty,
				"%% ORR Group %s not removed as '%s' is not found OR configured on neighbor(s)\n",
				name, name);
		return ret;
	}

	primary = peer_and_group_lookup_vty(vty, primary_str);
	if (!primary || !peer_af_flag_check(primary, afi, safi,
					    PEER_FLAG_REFLECTOR_CLIENT)) {
		vty_out(vty,
			"%% Primary Root is not a Route Reflector Client\n");
		return ret;
	}

	if (secondary_str) {
		secondary = peer_and_group_lookup_vty(vty, secondary_str);
		if (!secondary ||
		    !peer_af_flag_check(secondary, afi, safi,
					PEER_FLAG_REFLECTOR_CLIENT)) {
			vty_out(vty,
				"%% Secondary Root is not a Route Reflector Client\n");
			return ret;
		}
	}

	if (tertiary_str) {
		tertiary = peer_and_group_lookup_vty(vty, tertiary_str);
		if (!tertiary ||
		    !peer_af_flag_check(tertiary, afi, safi,
					PEER_FLAG_REFLECTOR_CLIENT)) {
			vty_out(vty,
				"%% Tertiary Root is not a Route Reflector Client\n");
			return ret;
		}
	}
	return bgp_afi_safi_orr_group_set(bgp, afi, safi, name, primary,
					  secondary, tertiary);
}

/* Set optimal route reflection group name to the peer. */
int peer_orr_group_set_vty(struct vty *vty, const char *ip_str, afi_t afi,
			   safi_t safi, const char *orr_group_name, bool set)
{
	int ret = CMD_WARNING_CONFIG_FAILED;
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, ip_str);
	if (!peer)
		return ret;

	if (!peer_af_flag_check(peer, afi, safi, PEER_FLAG_REFLECTOR_CLIENT)) {
		vty_out(vty, "%% Neighbor %s is not a Route Reflector Client\n",
			peer->host);
		return ret;
	}

	if (set) {
		ret = peer_orr_group_set(peer, afi, safi, orr_group_name);
		if (ret != CMD_SUCCESS)
			vty_out(vty, "%% ORR Group '%s' is not configured\n",
				orr_group_name);
	} else {
		ret = peer_orr_group_unset(peer, afi, safi, orr_group_name);
		if (ret == CMD_ERR_NO_MATCH)
			vty_out(vty,
				"%% ORR Group '%s' is not configured on %s\n",
				orr_group_name, peer->host);
		else if (ret == CMD_WARNING)
			vty_out(vty,
				"%% %s is one of the root nodes of ORR Group '%s'.\n",
				peer->host, orr_group_name);
	}
	return bgp_vty_return(vty, ret);
}

void bgp_config_write_orr(struct vty *vty, struct bgp *bgp, afi_t afi,
			  safi_t safi)
{
	struct list *orr_group_list;
	struct listnode *node;
	struct bgp_orr_group *orr_group;

	orr_group_list = bgp->orr_group[afi][safi];
	if (!orr_group_list)
		return;

	for (ALL_LIST_ELEMENTS_RO(orr_group_list, node, orr_group)) {
		/* optimal route reflection configuration */
		vty_out(vty, "  optimal-route-reflection %s", orr_group->name);
		if (orr_group->primary)
			vty_out(vty, " %s", orr_group->primary->host);
		if (orr_group->secondary)
			vty_out(vty, " %s", orr_group->secondary->host);
		if (orr_group->tertiary)
			vty_out(vty, " %s", orr_group->tertiary->host);
		vty_out(vty, "\n");
	}
}

static void bgp_show_orr_group(struct vty *vty, struct bgp_orr_group *orr_group,
			       afi_t afi, safi_t safi)
{
	char *rrclient = NULL;
	struct listnode *node;
	struct bgp_orr_igp_metric *igp_metric = NULL;
	struct list *orr_group_rrclient_list = NULL;
	struct list *orr_group_igp_metric_info = NULL;

	if (!orr_group)
		return;

	vty_out(vty, "\nORR group: %s, %s\n", orr_group->name,
		get_afi_safi_str(afi, safi, false));
	vty_out(vty, "Configured root:");
	vty_out(vty, " primary: %pBP,", orr_group->primary);
	vty_out(vty, " secondary: %pBP,", orr_group->secondary);
	vty_out(vty, " tertiary: %pBP\n", orr_group->tertiary);
	vty_out(vty, "Active Root: %pBP\n", orr_group->active);

	orr_group_rrclient_list = orr_group->rr_client_list;
	if (!orr_group_rrclient_list)
		return;

	vty_out(vty, "\nRR Clients mapped:\n");

	for (ALL_LIST_ELEMENTS_RO(orr_group_rrclient_list, node, rrclient))
		vty_out(vty, "%s\n", rrclient);

	vty_out(vty, "\nNumber of mapping entries: %d\n\n",
		orr_group_rrclient_list->count);


	orr_group_igp_metric_info = orr_group->igp_metric_info;
	if (!orr_group_igp_metric_info)
		return;
	vty_out(vty, "Prefix\t\t\t\t\t\tCost\n");
	for (ALL_LIST_ELEMENTS_RO(orr_group_igp_metric_info, node,
				  igp_metric)) {
		vty_out(vty, "%pFX\t\t\t\t\t\t%d\n", &igp_metric->prefix,
			igp_metric->igp_metric);
	}
	vty_out(vty, "\nNumber of mapping entries: %d\n\n",
		orr_group_igp_metric_info->count);
}

int bgp_show_orr(struct vty *vty, struct bgp *bgp, afi_t afi, safi_t safi,
		 const char *orr_group_name, uint8_t show_flags)
{
	struct listnode *node;
	struct bgp_orr_group *orr_group = NULL;
	struct list *orr_group_list = NULL;
	int ret = 0;

	assert(bgp);

	/* Display the matching entries for the given ORR Group */
	if (orr_group_name) {
		orr_group = bgp_orr_group_lookup_by_name(bgp, afi, safi,
							 orr_group_name);
		if (!orr_group) {
			vty_out(vty, "%% ORR Group %s not found\n",
				orr_group_name);
			return CMD_WARNING;
		}
		bgp_show_orr_group(vty, orr_group, afi, safi);
		return ret;
	}
	orr_group_list = bgp->orr_group[afi][safi];
	if (!orr_group_list)
		return ret;

	for (ALL_LIST_ELEMENTS_RO(orr_group_list, node, orr_group))
		bgp_show_orr_group(vty, orr_group, afi, safi);

	return ret;
}

/* Check if the Route Reflector Client belongs to any ORR Group */
bool peer_orr_rrclient_check(struct peer *peer, afi_t afi, safi_t safi)
{
	char *rrclient = NULL;
	struct listnode *node;
	struct list *orr_group_list = NULL;
	struct list *orr_group_rrclient_list = NULL;
	struct bgp_orr_group *orr_group = NULL;

	assert(peer && peer->bgp);

	orr_group_list = peer->bgp->orr_group[afi][safi];
	if (!orr_group_list)
		return false;

	for (ALL_LIST_ELEMENTS_RO(orr_group_list, node, orr_group)) {
		/*Check if peer configured as primary/secondary/tertiary root */
		if ((orr_group->primary &&
		     strmatch(peer->host, orr_group->primary->host)) ||
		    (orr_group->secondary &&
		     strmatch(peer->host, orr_group->secondary->host)) ||
		    (orr_group->tertiary &&
		     strmatch(peer->host, orr_group->tertiary->host)))
			return true;
		/*
		 * Check if peer is mapped to any ORR Group in this
		 * Address Family.
		 */
		orr_group_rrclient_list = orr_group->rr_client_list;
		if (!orr_group_rrclient_list)
			continue;

		for (ALL_LIST_ELEMENTS_RO(orr_group_rrclient_list, node,
					  rrclient))
			if (strmatch(rrclient, peer->host))
				return true;
	}
	return false;
}

static void
bgp_peer_update_orr_group_active_root(struct peer *peer, afi_t afi, safi_t safi,
				      struct bgp_orr_group *orr_group)
{
	assert(peer && orr_group);

	/* Nothing to do if this peer is not one of the root nodes */
	if (!is_orr_root_node(orr_group, peer->host))
		return;

	/* Root is reachable and group member, update Active Root if needed */
	if (is_peer_active_eligible(peer, afi, safi, orr_group->name)) {
		/* Nothing to do, if this is the current Active Root */
		if (is_orr_active_root(orr_group, peer->host))
			return;

		/* If Active is null, update this node as Active Root */
		if (!orr_group->active) {
			orr_group->active = peer;
			bgp_orr_igp_metric_register(orr_group, true);
			return;
		}

		/* If this is Primary and current Active is not Primary */
		if (is_orr_primary_root(orr_group, peer->host)) {
			bgp_orr_igp_metric_register(orr_group, false);
			orr_group->active = peer;
			bgp_orr_igp_metric_register(orr_group, true);
			return;
		}

		/*
		 * If this is Secondary and current Active is not
		 * Primary/Secondary
		 */
		if (is_orr_secondary_root(orr_group, peer->host)) {
			if (is_orr_active_root(orr_group,
					       orr_group->primary->host))
				return;
			bgp_orr_igp_metric_register(orr_group, false);
			orr_group->active = peer;
			bgp_orr_igp_metric_register(orr_group, true);
			return;
		}
		return;
	}

	/* Non Active Root is unreachable, so nothing to do */
	if (!is_orr_active_root(orr_group, peer->host))
		return;

	if (is_orr_primary_root(orr_group, peer->host)) {
		/* If secondary is reachable, update it as Active */
		if (is_peer_active_eligible(orr_group->secondary, afi, safi,
					    orr_group->name)) {
			bgp_orr_igp_metric_register(orr_group, false);

			orr_group->active = orr_group->secondary;
			bgp_orr_igp_metric_register(orr_group, true);
			return;
		}

		/* If tertiary is reachable, update it as Active */
		if (is_peer_active_eligible(orr_group->tertiary, afi, safi,
					    orr_group->name)) {
			bgp_orr_igp_metric_register(orr_group, false);

			orr_group->active = orr_group->tertiary;
			bgp_orr_igp_metric_register(orr_group, true);
			return;
		}
	} else {
		if (is_orr_secondary_root(orr_group, peer->host)) {
			/* If tertiary is reachable, update it as Active */
			if (is_peer_active_eligible(orr_group->tertiary, afi,
						    safi, orr_group->name)) {
				bgp_orr_igp_metric_register(orr_group, false);

				orr_group->active = orr_group->tertiary;
				bgp_orr_igp_metric_register(orr_group, true);
				return;
			}
		}
	}

	/* Assign Active as null */
	bgp_orr_igp_metric_register(orr_group, false);
	orr_group->active = NULL;

	bgp_orr_debug("%s: For %s, ORR Group '%s' has no active root", __func__,
		      get_afi_safi_str(afi, safi, false),
		      peer->orr_group_name[afi][safi]);
}

void bgp_peer_update_orr_active_roots(struct peer *peer)
{
	afi_t afi;
	safi_t safi;
	struct bgp_orr_group *orr_group;

	assert(peer && peer->bgp);

	FOREACH_AFI_SAFI (afi, safi) {
		if (!peer->orr_group_name[afi][safi])
			continue;

		/* Get BGP ORR entry for the given address-family */
		orr_group = bgp_orr_group_lookup_by_name(
			peer->bgp, afi, safi, peer->orr_group_name[afi][safi]);
		assert(orr_group);

		/* Free ORR related memory. */
		if (peer->status != Deleted) {
			bgp_peer_update_orr_group_active_root(peer, afi, safi,
							      orr_group);
			continue;
		}

		if (!is_orr_root_node(orr_group, peer->host)) {
			peer_orr_group_unset(peer, afi, safi,
					     peer->orr_group_name[afi][safi]);
			continue;
		}

		if (is_orr_primary_root(orr_group, peer->host)) {
			orr_group->primary = orr_group->secondary;
			orr_group->secondary = orr_group->tertiary;
		} else if (is_orr_secondary_root(orr_group, peer->host))
			orr_group->secondary = orr_group->tertiary;
		orr_group->tertiary = NULL;

		bgp_afi_safi_orr_group_set(peer->bgp, afi, safi,
					   orr_group->name, orr_group->primary,
					   orr_group->secondary,
					   orr_group->tertiary);
		peer_orr_group_unset(peer, afi, safi,
				     peer->orr_group_name[afi][safi]);
	}
}

/* IGP metric calculated from Active Root */
static int bgp_orr_igp_metric_update(struct orr_igp_metric_info *table)
{
	afi_t afi;
	safi_t safi;
	bool add = false;
	bool root_found = false;
	uint32_t instId = 0;
	uint32_t numEntries = 0;
	uint32_t entry = 0;
	uint8_t proto = ZEBRA_ROUTE_MAX;
	struct bgp *bgp = NULL;
	struct prefix pfx, root = {0};

	struct list *orr_group_list = NULL;
	struct bgp_orr_group *group = NULL;
	struct listnode *node, *nnode;

	struct bgp_orr_igp_metric *igp_metric = NULL;
	struct list *bgp_orr_igp_metric = NULL;

	bgp = bgp_get_default();
	assert(bgp && table);

	proto = table->proto;
	afi = family2afi(table->root.family);
	safi = table->safi;
	instId = table->instId;
	add = table->add;
	numEntries = table->num_entries;
	prefix_copy(&root, &table->root);

	if ((proto != ZEBRA_ROUTE_OSPF) && (proto != ZEBRA_ROUTE_OSPF6) &&
	    (proto != ZEBRA_ROUTE_ISIS)) {
		bgp_orr_debug("%s: Message received from unsupported protocol",
			      __func__);
		return -1;
	}

	orr_group_list = bgp->orr_group[afi][safi];
	if (!orr_group_list) {
		bgp_orr_debug(
			"%s: Address family %s has no ORR Groups configured",
			__func__, get_afi_safi_str(afi, safi, false));
		return -1;
	}

	if (BGP_DEBUG(optimal_route_reflection, ORR)) {
		zlog_debug(
			"[BGP-ORR] %s: Received metric update from protocol %s instance %d",
			__func__,
			proto == ZEBRA_ROUTE_ISIS
				? "ISIS"
				: (proto == ZEBRA_ROUTE_OSPF ? "OSPF"
							     : "OSPF6"),
			instId);
		zlog_debug("[BGP-ORR] %s: Address family %s", __func__,
			   get_afi_safi_str(afi, safi, false));
		zlog_debug("[BGP-ORR] %s: Root %pFX", __func__, &root);
		zlog_debug("[BGP-ORR] %s: Number of entries to be %s %d",
			   __func__, add ? "added" : "deleted", numEntries);
		zlog_debug("[BGP-ORR] %s: Prefix (Cost) :", __func__);
		for (entry = 0; entry < numEntries; entry++)
			zlog_debug("[BGP-ORR] %s: %pFX (%d)", __func__,
				   &table->nexthop[entry].prefix,
				   table->nexthop[entry].metric);
	}
	/*
	 * Update IGP metric info of all ORR Groups having this as active root
	 */
	for (ALL_LIST_ELEMENTS_RO(orr_group_list, node, group)) {
		if (str2prefix(group->active->host, &pfx) == 0) {
			bgp_orr_debug("%s: Malformed prefix for %pBP", __func__,
				      group->active);
			continue;
		}
		/*
		 * Copy IGP info if root matches with the active root of the
		 * group
		 */
		if (prefix_cmp(&pfx, &root) == 0) {
			if (add) {
				/* Add new routes */
				if (!group->igp_metric_info)
					group->igp_metric_info = list_new();

				bgp_orr_igp_metric = group->igp_metric_info;
				if (!bgp_orr_igp_metric)
					bgp_orr_igp_metric_register(group,
								    false);
				assert(bgp_orr_igp_metric);

				for (entry = 0; entry < numEntries; entry++) {
					igp_metric = XCALLOC(
						MTYPE_ORR_IGP_INFO,
						sizeof(struct
						       bgp_orr_igp_metric));
					if (!igp_metric)
						bgp_orr_igp_metric_register(
							group, false);

					prefix_copy(
						&igp_metric->prefix,
						&table->nexthop[entry].prefix);
					igp_metric->igp_metric =
						table->nexthop[entry].metric;
					listnode_add(bgp_orr_igp_metric,
						     igp_metric);
				}
			} else {
				/* Delete old routes */
				for (entry = 0; entry < numEntries; entry++) {
					for (ALL_LIST_ELEMENTS(
						     group->igp_metric_info,
						     node, nnode, igp_metric)) {
						if (prefix_cmp(
							    &igp_metric->prefix,
							    &table->nexthop[entry]
								     .prefix))
							continue;
						listnode_delete(
							group->igp_metric_info,
							igp_metric);
						XFREE(MTYPE_ORR_IGP_INFO,
						      igp_metric);
					}
				}
			}
			root_found = true;
			break;
		}
	}
	/* Received IGP for root node thats not found in ORR active roots */
	if (!root_found) {
		bgp_orr_debug(
			"%s: Received IGP SPF information for root %pFX which is not an ORR active root",
			__func__, &root);
	}
	assert(root_found);
	return 0;
}

/* Register with IGP for sending SPF info */
static void bgp_orr_igp_metric_register(struct bgp_orr_group *orr_group,
					bool reg)
{
	int ret;
	struct orr_igp_metric_reg msg;
	struct prefix p;
	char *rr_client = NULL;

	assert(orr_group);

	if (!orr_group->active)
		return;

	memset(&msg, 0, sizeof(msg));
	ret = str2prefix(orr_group->active->host, &p);

	/* Malformed prefix */
	assert(ret);

	/* Check if the active root is part of this ORR group */
	rr_client = bgp_orr_group_rrclient_lookup(orr_group,
						  orr_group->active->host);
	if (reg && !rr_client) {
		bgp_orr_debug(
			"%s: active root %pBP is not part of this ORR group",
			__func__, orr_group->active);
		return;
	}

	msg.reg = reg;
	msg.proto = ZEBRA_ROUTE_BGP;
	msg.safi = orr_group->safi;
	prefix_copy(&msg.prefix, &p);
	strlcpy(msg.group_name, orr_group->name, sizeof(msg.group_name));

	bgp_orr_debug(
		"%s: %s with IGP for metric calculation from location %pFX",
		__func__, reg ? "Register" : "Unregister", &msg.prefix);

	if (zclient_send_opaque(zclient, ORR_IGP_METRIC_REGISTER,
				(uint8_t *)&msg,
				sizeof(msg)) == ZCLIENT_SEND_FAILURE)
		zlog_warn("[BGP-ORR] %s: Failed to send message to IGP.",
			  __func__);

	/* Free IGP metric info calculated from previous active location */
	if (!reg && orr_group->igp_metric_info)
		list_delete(&orr_group->igp_metric_info);
}

/* BGP ORR message processing */
int bgg_orr_message_process(enum bgp_orr_msg_type msg_type, void *msg)
{
	int ret = 0;

	assert(msg && msg_type > BGP_ORR_IMSG_INVALID &&
	       msg_type < BGP_ORR_IMSG_MAX);
	switch (msg_type) {
	case BGP_ORR_IMSG_GROUP_CREATE:
		break;
	case BGP_ORR_IMSG_GROUP_DELETE:
		break;
	case BGP_ORR_IMSG_GROUP_UPDATE:
		break;
	case BGP_ORR_IMSG_SET_ORR_ON_PEER:
		break;
	case BGP_ORR_IMSG_UNSET_ORR_ON_PEER:
		break;
	case BGP_ORR_IMSG_IGP_METRIC_UPDATE:
		ret = bgp_orr_igp_metric_update(
			(struct orr_igp_metric_info *)msg);
		break;
	case BGP_ORR_IMSG_SHOW_ORR:
		/* bgp_show_orr */
		break;
	case BGP_ORR_IMSG_SHOW_ORR_GROUP:
		/* bgp_show_orr_group */
		break;
	default:
		break;
	}

	/* Free Memory */
	return ret;
}

/*
 * Cleanup ORR information - invoked at the time of bgpd exit or
 * when the BGP instance (default) is being freed.
 */
void bgp_orr_cleanup(struct bgp *bgp)
{
	afi_t afi;
	safi_t safi;
	struct listnode *node, *nnode;
	struct bgp_orr_group *orr_group;

	assert(bgp);

	if (!bgp->orr_group_count)
		return;

	FOREACH_AFI_SAFI (afi, safi) {
		for (ALL_LIST_ELEMENTS(bgp->orr_group[afi][safi], node, nnode,
				       orr_group))
			bgp_orr_group_free(orr_group);
	}
}
