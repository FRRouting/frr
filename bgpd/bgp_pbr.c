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
