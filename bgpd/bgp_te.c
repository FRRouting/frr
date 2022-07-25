/* BGP Endpoint End Point Tracking Database
 *
 * Copyright 2022 6WIND S.A.
 *
 * This file is part of FRRouting.
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
#include "memory.h"
#include "network.h"
#include "hook.h"

#include "lib/ipaddr.h"
#include "lib/srte.h"
#include "lib/zapi_client.h"
#include "lib/zapi_triggered_srte.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_te.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_nht.h"
#include "bgpd/bgp_memory.h"
#include "bgpd/bgp_zebra.h"

DEFINE_MTYPE_STATIC(BGPD, BGP_TE_ENTRY, "BGP TE Entry");

extern struct zclient *zclient;

static bool bgp_te_on;

static int te_debug_conf, te_debug_term;

#define TE_DEBUG(...)                                                          \
	if (te_debug_conf || te_debug_term) {                                  \
		zlog_debug("BGP-TE: " __VA_ARGS__);                            \
	}

RB_GENERATE(bgp_te_entry_head, bgp_te_entry, entry, bgp_te_entry_compare)

struct bgp_te_entry_head bgp_te_entries = RB_INITIALIZER(&bgp_te_entries);

static int bgp_zebra_te_register(vrf_id_t vrf_id, uint32_t color,
				 struct ipaddr *endpoint)
{
	enum zclient_send_status ret;

	if (zclient == NULL) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("zclient == NULL, invalid");
		return -1;
	}
	ret = zapi_tsrte_registration_send(zclient, color, endpoint, true);
	if (ret == ZCLIENT_SEND_FAILURE)
		return -1;

	return 0;
}

static int bgp_zebra_te_unregister(vrf_id_t vrf_id, uint32_t color,
				   struct ipaddr *endpoint)
{
	enum zclient_send_status ret;

	if (zclient == NULL) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("zclient == NULL, invalid");
		return -1;
	}
	ret = zapi_tsrte_registration_send(zclient, color, endpoint, false);
	if (ret == ZCLIENT_SEND_FAILURE)
		return -1;

	return 0;
}

int bgp_te_entry_compare(const struct bgp_te_entry *a,
			 const struct bgp_te_entry *b)
{
	return sr_policy_compare(&a->endpoint, &b->endpoint, a->color,
				 b->color);
}

struct bgp_te_entry *bgp_te_entry_find(uint32_t color, struct ipaddr *ipaddr)
{
	struct bgp_te_entry search;

	search.color = color;
	search.endpoint = *ipaddr;
	return RB_FIND(bgp_te_entry_head, &bgp_te_entries, &search);
}

static void bgp_te_entry_remove(struct bgp_te_entry *bgp_te)
{
	RB_REMOVE(bgp_te_entry_head, &bgp_te_entries, bgp_te);
	XFREE(MTYPE_BGP_TE_ENTRY, bgp_te);
}

static struct bgp_te_entry *bgp_te_entry_add(uint32_t color,
					     struct ipaddr *endpoint)
{
	struct bgp_te_entry *bgp_te;

	bgp_te = XCALLOC(MTYPE_BGP_TE_ENTRY, sizeof(*bgp_te));
	bgp_te->color = color;
	bgp_te->endpoint = *endpoint;
	bgp_te->binding_sid = MPLS_LABEL_NONE;
	RB_INSERT(bgp_te_entry_head, &bgp_te_entries, bgp_te);

	return bgp_te;
}

static int bgp_te_provision_ipaddr(struct bgp_nexthop_cache *bnc,
				   struct ipaddr *endpoint)
{
	if (bnc->prefix.family == AF_INET) {
		endpoint->ipa_type = IPADDR_V4;
		endpoint->ip._v4_addr = bnc->prefix.u.prefix4;
	} else if (bnc->prefix.family == AF_INET6) {
		endpoint->ipa_type = IPADDR_V6;
		memcpy(&endpoint->ip._v6_addr, &bnc->prefix.u.prefix6,
		       sizeof(struct in6_addr));
	} else
		return 0;
	return 1;
}

static int bgp_te_create_context(struct bgp_nexthop_cache *bnc)
{
	struct ipaddr ip_endpoint = {};
	struct bgp_te_entry *bgp_te;
	char endpoint[IPADDR_STRING_SIZE];

	if (!bgp_te_provision_ipaddr(bnc, &ip_endpoint))
		return 0;

	if (CHECK_FLAG(bnc->flags, BGP_NEXTHOP_TE_REGISTER)) {
		bgp_zebra_te_register(VRF_DEFAULT, bnc->srte_color,
				      &ip_endpoint);
		return 1;
	}

	bgp_te = bgp_te_entry_add(bnc->srte_color, &ip_endpoint);
	if (!bgp_te)
		return 0;
	bgp_zebra_te_register(VRF_DEFAULT, bnc->srte_color, &ip_endpoint);
	ipaddr2str(&bgp_te->endpoint, endpoint, sizeof(endpoint));
	TE_DEBUG("TE entry Color %u NH %s added", bnc->srte_color, endpoint);
	bgp_te->bnc = bnc;
	return 1;
}

static int bgp_te_delete_context(struct bgp_nexthop_cache *bnc)
{
	struct ipaddr ip_endpoint = {};
	struct bgp_te_entry *bgp_te;
	char endpoint[IPADDR_STRING_SIZE];

	if (!bgp_te_provision_ipaddr(bnc, &ip_endpoint))
		return 0;

	bgp_te = bgp_te_entry_find(bnc->srte_color, &ip_endpoint);
	if (!bgp_te)
		return 0;
	ipaddr2str(&bgp_te->endpoint, endpoint, sizeof(endpoint));
	bgp_zebra_te_unregister(VRF_DEFAULT, bnc->srte_color, &ip_endpoint);
	TE_DEBUG("TE entry Color %u NH %s removed", bnc->srte_color, endpoint);
	bgp_te_entry_remove(bgp_te);
	return 1;
}

static int bgp_te_nht_update(struct bgp_nexthop_cache *bnc, bool created)
{
	if (!bnc->srte_color)
		return 0;
	if (!bnc->bgp || bnc->bgp->vrf_id != VRF_DEFAULT)
		return 0;
	if (created) {
		if (!bgp_te_on)
			return 0;
		if (bgp_te_create_context(bnc))
			SET_FLAG(bnc->flags, BGP_NEXTHOP_TE_REGISTER);
		return 1;
	} else {
		if (!CHECK_FLAG(bnc->flags, BGP_NEXTHOP_TE_REGISTER)) {
			TE_DEBUG("%s(): TE_REGISTER not present for %p",
				 __func__, bnc);
			return 0;
		}
		bgp_te_delete_context(bnc);
	}
	return 1;
}

static void bgp_te_add_te_entries(void)
{
	afi_t afi;
	struct bgp_nexthop_cache_head(*tree)[AFI_MAX];
	struct bgp *bgp = bgp_get_default();
	struct bgp_nexthop_cache *bnc;

	if (!bgp)
		return;

	tree = &bgp->nexthop_cache_table;

	for (afi = AFI_IP; afi < AFI_MAX; afi++) {
		frr_each (bgp_nexthop_cache, &(*tree)[afi], bnc) {
			if (bnc->nht_info)
				continue;
			bgp_te_nht_update(bnc, true);
		}
	}
}

static void bgp_te_flush_te_entries(void)
{
	struct bgp_te_entry *entry;

	while (!RB_EMPTY(bgp_te_entry_head, &bgp_te_entries)) {
		entry = RB_ROOT(bgp_te_entry_head, &bgp_te_entries);
		/* XXX inform Pathd */
		if (entry->bnc)
			SET_FLAG(entry->bnc->flags, BGP_NEXTHOP_TE_REGISTER);
		bgp_te_entry_remove(entry);
	}
}

/* Register a new client.  If the client registered previously, the client
 * either restarted or changed configuration
 * - flush BGP TE contexts
 * - if origin == BGP, then re-create BGP TE context
 *
 * @param client_daemon_id	client process
 * @param origin	        protocol_origin
 *
 * @return			0 on success, -1 otherwise.
 */
static int bgp_te_policy_process_client_ready(
		const struct zapi_client_daemon_id *const client_daemon_id,
		const enum srte_protocol_origin *origin)
{
	int client;

	/* For now, there can be only one client.  If a new client shows up,
	 * assume pathd restarted and clean up the old information.
	 */
	client = zapi_client_find_client(client_daemon_id);
	if (client < 0)
		goto out;

	/* BGP TE colored registered contexts are getting flushed */
	if (zapi_client_del_client(client)) {
		zlog_warn("%s Unable to replace client", __func__);
		return -1;
	}

out:
	/* do not continue if decision maker is not BGP */
	if (*origin != SRTE_ORIGIN_BGP) {
		if (!bgp_te_on)
			return -1;
		TE_DEBUG("BGP TE capability disabled");
		bgp_te_on = false;
		/* need to flush contexts */
		bgp_te_flush_te_entries();
		return -1;
	}

	if (zapi_client_get_client(client_daemon_id) < 0)
		return -1;
	if (bgp_te_on)
		return -1;
	TE_DEBUG("BGP TE capability enabled");
	bgp_te_on = true;
	/* Notify the client of available BGP colored next-hops from BGP updates
	 */
	/* need to update contexts */
	bgp_te_add_te_entries();
	return 0;
}

int bgp_te_process_tsrte_client_ready(struct stream *s)
{
	int ret;
	struct zapi_client_daemon_id client_daemon_id;
	enum srte_protocol_origin origin;

	ret = zapi_tsrte_client_ready_decode(s, &client_daemon_id,
					     &origin);
	if (ret)
		return -1;
	ret = bgp_te_policy_process_client_ready(&client_daemon_id,
						 &origin);
	return ret;
}

int bgp_te_process_tsrte_bgp_update(struct stream *s)
{
	uint32_t srte_color;
	struct ipaddr ipaddr = {};
	char policy_name[SRTE_POLICY_NAME_MAX_LENGTH];
	char segmentlist_name[SRTE_SEGMENT_LIST_NAME_MAX_LENGTH];
	struct bgp_te_entry *entry;
	mpls_label_t bsid;
	int ret;

	ret = zapi_tsrte_update_decode(
			s, &srte_color, &ipaddr, &bsid, segmentlist_name,
			sizeof(segmentlist_name), policy_name,
			sizeof(policy_name));
	if (ret == -1)
		return -1;
	entry = bgp_te_entry_find(srte_color, &ipaddr);
	if (!entry)
		return -1;
	entry->binding_sid = bsid;
	memcpy(&entry->name, policy_name, sizeof(policy_name));
	memcpy(&entry->segmentlistname, segmentlist_name,
	       sizeof(segmentlist_name));
	return ret;
}

static int bgp_te_write_debug(struct vty *vty, bool running)
{
	if (te_debug_conf && running) {
		vty_out(vty, "debug bgp te\n");
		return 1;
	}
	if ((te_debug_conf || te_debug_term) && !running) {
		vty_out(vty, "  BGP TE debugging is on\n");
		return 1;
	}
	return 0;
}

DEFUN(debug_te, debug_te_cmd, "debug bgp te",
      DEBUG_STR BGP_STR "Enable debugging for TE\n")
{
	if (vty->node == CONFIG_NODE)
		te_debug_conf = 1;
	else
		te_debug_term = 1;
	return CMD_SUCCESS;
}

DEFUN(no_debug_te, no_debug_te_cmd, "no debug bgp te",
      NO_STR DEBUG_STR BGP_STR "Disable debugging for TE\n")
{
	if (vty->node == CONFIG_NODE)
		te_debug_conf = 0;
	else
		te_debug_term = 0;
	return CMD_SUCCESS;
}

void bgp_te_init(void)
{
	bgp_te_on = false;
	hook_register(bgp_hook_nht_update, bgp_te_nht_update);
	hook_register(bgp_hook_config_write_debug, &bgp_te_write_debug);
	te_debug_conf = 0;
	te_debug_term = 0;

	install_element(CONFIG_NODE, &debug_te_cmd);
	install_element(ENABLE_NODE, &debug_te_cmd);
	install_element(CONFIG_NODE, &no_debug_te_cmd);
	install_element(ENABLE_NODE, &no_debug_te_cmd);
}

void bgp_te_show_nexthops_detail(struct vty *vty, struct bgp *bgp,
				 struct bgp_nexthop_cache *bnc)
{
	struct ipaddr ip_endpoint = {};
	struct bgp_te_entry *bgp_te;
	char binding_sid[16] = "-";

	if (!bnc->srte_color)
		return;
	if (!bgp_te_provision_ipaddr(bnc, &ip_endpoint))
		return;
	bgp_te = bgp_te_entry_find(bnc->srte_color, &ip_endpoint);
	if (bgp_te && bgp_te->name[0] != '\0') {
		if (bgp_te->binding_sid != MPLS_LABEL_NONE)
			snprintf(binding_sid, sizeof(binding_sid), "%u",
				 bgp_te->binding_sid);
		vty_out(vty, "  policy %s, bsid %s", bgp_te->name, binding_sid);
		if (bgp_te->binding_sid != MPLS_LABEL_NONE) {
			vty_out(vty, " (seg-list %s)", bgp_te->segmentlistname);
		}
		vty_out(vty, "\n");
	}
}
