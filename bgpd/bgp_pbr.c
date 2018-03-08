/*
 * BGP pbr
 * Copyright (C) 6WIND
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "zebra.h"
#include "prefix.h"
#include "zclient.h"
#include "jhash.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_pbr.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_flowspec_util.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"

static int sprintf_bgp_pbr_match_val(char *str, struct bgp_pbr_match_val *mval,
				     const char *prepend)
{
	char *ptr = str;

	if (prepend)
		ptr += sprintf(ptr, "%s", prepend);
	else {
		if (mval->unary_operator & OPERATOR_UNARY_OR)
			ptr += sprintf(ptr, ", or ");
		if (mval->unary_operator & OPERATOR_UNARY_AND)
			ptr += sprintf(ptr, ", and ");
	}
	if (mval->compare_operator & OPERATOR_COMPARE_LESS_THAN)
		ptr += sprintf(ptr, "<");
	if (mval->compare_operator & OPERATOR_COMPARE_GREATER_THAN)
		ptr += sprintf(ptr, ">");
	if (mval->compare_operator & OPERATOR_COMPARE_EQUAL_TO)
		ptr += sprintf(ptr, "=");
	if (mval->compare_operator & OPERATOR_COMPARE_EXACT_MATCH)
		ptr += sprintf(ptr, "match");
	ptr += sprintf(ptr, " %u", mval->value);
	return (int)(ptr - str);
}

#define INCREMENT_DISPLAY(_ptr, _cnt) do { \
		if (_cnt) \
			(_ptr) += sprintf((_ptr), "; "); \
		_cnt++; \
	} while (0)

/* return 1 if OK, 0 if validation should stop) */
static int bgp_pbr_validate_policy_route(struct bgp_pbr_entry_main *api)
{
	/* because bgp pbr entry may contain unsupported
	 * combinations, a message will be displayed here if
	 * not supported.
	 * for now, only match/set supported is
	 * - combination src/dst => redirect nexthop [ + rate]
	 * - combination src/dst => redirect VRF [ + rate]
	 * - combination src/dst => drop
	 */
	if (api->match_src_port_num || api->match_dst_port_num
	    || api->match_port_num || api->match_protocol_num
	    || api->match_icmp_type_num || api->match_icmp_type_num
	    || api->match_packet_length_num || api->match_dscp_num
	    || api->match_tcpflags_num) {
		if (BGP_DEBUG(pbr, PBR))
			bgp_pbr_print_policy_route(api);
		zlog_err("BGP: some SET actions not supported by Zebra. ignoring.");
		return 0;
	}
	if (!(api->match_bitmask & PREFIX_SRC_PRESENT) &&
	    !(api->match_bitmask & PREFIX_DST_PRESENT)) {
		if (BGP_DEBUG(pbr, PBR))
			bgp_pbr_print_policy_route(api);
		zlog_err("BGP: SET actions without src or dst address can not operate. ignoring.");
		return 0;
	}
	return 1;
}

/* return -1 if build or validation failed */
static int bgp_pbr_build_and_validate_entry(struct prefix *p,
					    struct bgp_info *info,
					    struct bgp_pbr_entry_main *api)
{
	int ret;
	int i, action_count = 0;
	struct ecommunity *ecom;
	struct ecommunity_val *ecom_eval;
	struct bgp_pbr_entry_action *api_action;
	struct prefix *src = NULL, *dst = NULL;
	int valid_prefix = 0;
	afi_t afi = AFI_IP;

	/* extract match from flowspec entries */
	ret = bgp_flowspec_match_rules_fill((uint8_t *)p->u.prefix_flowspec.ptr,
				     p->u.prefix_flowspec.prefixlen, api);
	if (ret < 0)
		return -1;
	/* extract actiosn from flowspec ecom list */
	if (info && info->attr && info->attr->ecommunity) {
		ecom = info->attr->ecommunity;
		for (i = 0; i < ecom->size; i++) {
			ecom_eval = (struct ecommunity_val *)
				ecom->val + (i * ECOMMUNITY_SIZE);

			if (action_count > ACTIONS_MAX_NUM) {
				zlog_err("%s: flowspec actions exceeds limit (max %u)",
					 __func__, action_count);
				break;
			}
			api_action = &api->actions[action_count];

			if ((ecom_eval->val[1] ==
			     (char)ECOMMUNITY_REDIRECT_VRF) &&
			    (ecom_eval->val[0] ==
			     (char)ECOMMUNITY_ENCODE_TRANS_EXP ||
			     ecom_eval->val[0] ==
			     (char)ECOMMUNITY_EXTENDED_COMMUNITY_PART_2 ||
			     ecom_eval->val[0] ==
			     (char)ECOMMUNITY_EXTENDED_COMMUNITY_PART_3)) {
				struct ecommunity *eckey = ecommunity_new();
				struct ecommunity_val ecom_copy;

				memcpy(&ecom_copy, ecom_eval,
				       sizeof(struct ecommunity_val));
				ecom_copy.val[0] &=
					~ECOMMUNITY_ENCODE_TRANS_EXP;
				ecom_copy.val[1] = ECOMMUNITY_ROUTE_TARGET;
				ecommunity_add_val(eckey, &ecom_copy);

				api_action->action = ACTION_REDIRECT;
				api_action->u.redirect_vrf =
					get_first_vrf_for_redirect_with_rt(
								eckey);
				ecommunity_free(&eckey);
			} else if ((ecom_eval->val[0] ==
				    (char)ECOMMUNITY_ENCODE_REDIRECT_IP_NH) &&
				   (ecom_eval->val[1] ==
				    (char)ECOMMUNITY_REDIRECT_IP_NH)) {
				api_action->action = ACTION_REDIRECT_IP;
				api_action->u.zr.redirect_ip_v4.s_addr =
					info->attr->nexthop.s_addr;
				api_action->u.zr.duplicate = ecom_eval->val[7];
			} else {
				if (ecom_eval->val[0] !=
				    (char)ECOMMUNITY_ENCODE_TRANS_EXP)
					continue;
				ret = ecommunity_fill_pbr_action(ecom_eval,
								 api_action);
				if (ret != 0)
					continue;
			}
			api->action_num++;
		}
	}

	/* validate if incoming matc/action is compatible
	 * with our policy routing engine
	 */
	if (!bgp_pbr_validate_policy_route(api))
		return -1;

	/* check inconsistency in the match rule */
	if (api->match_bitmask & PREFIX_SRC_PRESENT) {
		src = &api->src_prefix;
		afi = family2afi(src->family);
		valid_prefix = 1;
	}
	if (api->match_bitmask & PREFIX_DST_PRESENT) {
		dst = &api->dst_prefix;
		if (valid_prefix && afi != family2afi(dst->family)) {
			if (BGP_DEBUG(pbr, PBR))
				bgp_pbr_print_policy_route(api);
			zlog_err("%s: inconsistency:  no match for afi src and dst (%u/%u)",
				 __func__, afi, family2afi(dst->family));
			return -1;
		}
	}
	return 0;
}

uint32_t bgp_pbr_match_hash_key(void *arg)
{
	struct bgp_pbr_match *pbm = (struct bgp_pbr_match *)arg;
	uint32_t key;

	key = jhash_1word(pbm->vrf_id, 0x4312abde);
	key = jhash_1word(pbm->flags, key);
	return jhash_1word(pbm->type, key);
}

int bgp_pbr_match_hash_equal(const void *arg1, const void *arg2)
{
	const struct bgp_pbr_match *r1, *r2;

	r1 = (const struct bgp_pbr_match *)arg1;
	r2 = (const struct bgp_pbr_match *)arg2;

	if (r1->vrf_id != r2->vrf_id)
		return 0;

	if (r1->type != r2->type)
		return 0;

	if (r1->flags != r2->flags)
		return 0;

	if (r1->action != r2->action)
		return 0;

	return 1;
}

uint32_t bgp_pbr_match_entry_hash_key(void *arg)
{
	struct bgp_pbr_match_entry *pbme;
	uint32_t key;

	pbme = (struct bgp_pbr_match_entry *)arg;
	key = prefix_hash_key(&pbme->src);
	key = jhash_1word(prefix_hash_key(&pbme->dst), key);

	return key;
}

int bgp_pbr_match_entry_hash_equal(const void *arg1, const void *arg2)
{
	const struct bgp_pbr_match_entry *r1, *r2;

	r1 = (const struct bgp_pbr_match_entry *)arg1;
	r2 = (const struct bgp_pbr_match_entry *)arg2;

	/* on updates, comparing
	 * backpointer is not necessary
	 */

	/* unique value is self calculated
	 */

	/* rate is ignored for now
	 */

	if (!prefix_same(&r1->src, &r2->src))
		return 0;

	if (!prefix_same(&r1->dst, &r2->dst))
		return 0;

	return 1;
}

uint32_t bgp_pbr_action_hash_key(void *arg)
{
	struct bgp_pbr_action *pbra;
	uint32_t key;

	pbra = (struct bgp_pbr_action *)arg;
	key = jhash_1word(pbra->table_id, 0x4312abde);
	key = jhash_1word(pbra->fwmark, key);
	return key;
}

int bgp_pbr_action_hash_equal(const void *arg1, const void *arg2)
{
	const struct bgp_pbr_action *r1, *r2;

	r1 = (const struct bgp_pbr_action *)arg1;
	r2 = (const struct bgp_pbr_action *)arg2;

	/* unique value is self calculated
	 * table and fwmark is self calculated
	 */
	if (r1->rate != r2->rate)
		return 0;

	if (r1->vrf_id != r2->vrf_id)
		return 0;

	if (memcmp(&r1->nh, &r2->nh, sizeof(struct nexthop)))
		return 0;
	return 1;
}

struct bgp_pbr_action *bgp_pbr_action_rule_lookup(uint32_t unique)
{
	return NULL;
}

struct bgp_pbr_match *bgp_pbr_match_ipset_lookup(vrf_id_t vrf_id,
						 uint32_t unique)
{
	return NULL;
}

struct bgp_pbr_match_entry *bgp_pbr_match_ipset_entry_lookup(vrf_id_t vrf_id,
						       char *ipset_name,
						       uint32_t unique)
{
	return NULL;
}

void bgp_pbr_init(struct bgp *bgp)
{
	bgp->pbr_match_hash =
		hash_create_size(8, bgp_pbr_match_hash_key,
				 bgp_pbr_match_hash_equal,
				 "Match Hash");
	bgp->pbr_action_hash =
		hash_create_size(8, bgp_pbr_action_hash_key,
				 bgp_pbr_action_hash_equal,
				 "Match Hash Entry");
}

void bgp_pbr_print_policy_route(struct bgp_pbr_entry_main *api)
{
	int i = 0;
	char return_string[512];
	char *ptr = return_string;
	char buff[64];
	int nb_items = 0;

	ptr += sprintf(ptr, "MATCH : ");
	if (api->match_bitmask & PREFIX_SRC_PRESENT) {
		struct prefix *p = &(api->src_prefix);

		ptr += sprintf(ptr, "@src %s", prefix2str(p, buff, 64));
		INCREMENT_DISPLAY(ptr, nb_items);
	}
	if (api->match_bitmask & PREFIX_DST_PRESENT) {
		struct prefix *p = &(api->dst_prefix);

		INCREMENT_DISPLAY(ptr, nb_items);
		ptr += sprintf(ptr, "@dst %s", prefix2str(p, buff, 64));
	}

	if (api->match_protocol_num)
		INCREMENT_DISPLAY(ptr, nb_items);
	for (i = 0; i < api->match_protocol_num; i++)
		ptr += sprintf_bgp_pbr_match_val(ptr, &api->protocol[i],
					i > 0 ? NULL : "@proto ");

	if (api->match_src_port_num)
		INCREMENT_DISPLAY(ptr, nb_items);
	for (i = 0; i < api->match_src_port_num; i++)
		ptr += sprintf_bgp_pbr_match_val(ptr, &api->src_port[i],
					i > 0 ? NULL : "@srcport ");

	if (api->match_dst_port_num)
		INCREMENT_DISPLAY(ptr, nb_items);
	for (i = 0; i < api->match_dst_port_num; i++)
		ptr += sprintf_bgp_pbr_match_val(ptr, &api->dst_port[i],
					 i > 0 ? NULL : "@dstport ");

	if (api->match_port_num)
		INCREMENT_DISPLAY(ptr, nb_items);
	for (i = 0; i < api->match_port_num; i++)
		ptr += sprintf_bgp_pbr_match_val(ptr, &api->port[i],
					 i > 0 ? NULL : "@port ");

	if (api->match_icmp_type_num)
		INCREMENT_DISPLAY(ptr, nb_items);
	for (i = 0; i < api->match_icmp_type_num; i++)
		ptr += sprintf_bgp_pbr_match_val(ptr, &api->icmp_type[i],
					 i > 0 ? NULL : "@icmptype ");

	if (api->match_icmp_code_num)
		INCREMENT_DISPLAY(ptr, nb_items);
	for (i = 0; i < api->match_icmp_code_num; i++)
		ptr += sprintf_bgp_pbr_match_val(ptr, &api->icmp_code[i],
					 i > 0 ? NULL : "@icmpcode ");

	if (api->match_packet_length_num)
		INCREMENT_DISPLAY(ptr, nb_items);
	for (i = 0; i < api->match_packet_length_num; i++)
		ptr += sprintf_bgp_pbr_match_val(ptr, &api->packet_length[i],
					 i > 0 ? NULL : "@plen ");

	if (api->match_dscp_num)
		INCREMENT_DISPLAY(ptr, nb_items);
	for (i = 0; i < api->match_dscp_num; i++)
		ptr += sprintf_bgp_pbr_match_val(ptr, &api->dscp[i],
					i > 0 ? NULL : "@dscp ");

	if (api->match_tcpflags_num)
		INCREMENT_DISPLAY(ptr, nb_items);
	for (i = 0; i < api->match_tcpflags_num; i++)
		ptr += sprintf_bgp_pbr_match_val(ptr, &api->tcpflags[i],
					 i > 0 ? NULL : "@tcpflags ");

	if (api->match_bitmask & FRAGMENT_PRESENT) {
		INCREMENT_DISPLAY(ptr, nb_items);
		ptr += sprintf(ptr, "@fragment %u", api->fragment.bitmask);
	}
	if (!nb_items)
		ptr = return_string;
	else
		ptr += sprintf(ptr, "; ");
	if (api->action_num)
		ptr += sprintf(ptr, "SET : ");
	nb_items = 0;
	for (i = 0; i < api->action_num; i++) {
		switch (api->actions[i].action) {
		case ACTION_TRAFFICRATE:
			INCREMENT_DISPLAY(ptr, nb_items);
			ptr += sprintf(ptr, "@set rate %f",
				       api->actions[i].u.r.rate);
			break;
		case ACTION_TRAFFIC_ACTION:
			INCREMENT_DISPLAY(ptr, nb_items);
			ptr += sprintf(ptr, "@action ");
			if (api->actions[i].u.za.filter
			    & TRAFFIC_ACTION_TERMINATE)
				ptr += sprintf(ptr,
					       " terminate (apply filter(s))");
			if (api->actions[i].u.za.filter
			    & TRAFFIC_ACTION_DISTRIBUTE)
				ptr += sprintf(ptr, " distribute");
			if (api->actions[i].u.za.filter
			    & TRAFFIC_ACTION_SAMPLE)
				ptr += sprintf(ptr, " sample");
			break;
		case ACTION_REDIRECT_IP:
			INCREMENT_DISPLAY(ptr, nb_items);
			char local_buff[INET_ADDRSTRLEN];

			if (inet_ntop(AF_INET,
				      &api->actions[i].u.zr.redirect_ip_v4,
				      local_buff, INET_ADDRSTRLEN) != NULL)
				ptr += sprintf(ptr,
					  "@redirect ip nh %s", local_buff);
			break;
		case ACTION_REDIRECT:
			INCREMENT_DISPLAY(ptr, nb_items);
			ptr += sprintf(ptr, "@redirect vrf %u",
				       api->actions[i].u.redirect_vrf);
			break;
		case ACTION_MARKING:
			INCREMENT_DISPLAY(ptr, nb_items);
			ptr += sprintf(ptr, "@set dscp %u",
				  api->actions[i].u.marking_dscp);
			break;
		default:
			break;
		}
	}
	zlog_info("%s", return_string);
}

void bgp_pbr_update_entry(struct bgp *bgp, struct prefix *p,
			 struct bgp_info *info, afi_t afi, safi_t safi,
			 bool nlri_update)
{
	struct bgp_pbr_entry_main api;

	if (afi == AFI_IP6)
		return; /* IPv6 not supported */
	if (safi != SAFI_FLOWSPEC)
		return; /* not supported */
	/* Make Zebra API structure. */
	memset(&api, 0, sizeof(api));
	api.vrf_id = bgp->vrf_id;
	api.afi = afi;

	if (bgp_pbr_build_and_validate_entry(p, info, &api) < 0) {
		zlog_err("%s: cancel updating entry in bgp pbr",
			 __func__);
		return;
	}
	/* TODO. update prefix and pbr hash contexts */
}

