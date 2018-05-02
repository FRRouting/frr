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
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_mplsvpn.h"

DEFINE_MTYPE_STATIC(BGPD, PBR_MATCH_ENTRY, "PBR match entry")
DEFINE_MTYPE_STATIC(BGPD, PBR_MATCH, "PBR match")
DEFINE_MTYPE_STATIC(BGPD, PBR_ACTION, "PBR action")

static int bgp_pbr_match_counter_unique;
static int bgp_pbr_match_entry_counter_unique;
static int bgp_pbr_action_counter_unique;
static int bgp_pbr_match_iptable_counter_unique;

struct bgp_pbr_match_iptable_unique {
	uint32_t unique;
	struct bgp_pbr_match *bpm_found;
};

struct bgp_pbr_match_entry_unique {
	uint32_t unique;
	struct bgp_pbr_match_entry *bpme_found;
};

struct bgp_pbr_action_unique {
	uint32_t unique;
	struct bgp_pbr_action *bpa_found;
};

static int bgp_pbr_action_walkcb(struct hash_backet *backet, void *arg)
{
	struct bgp_pbr_action *bpa = (struct bgp_pbr_action *)backet->data;
	struct bgp_pbr_action_unique *bpau = (struct bgp_pbr_action_unique *)
		arg;
	uint32_t unique = bpau->unique;

	if (bpa->unique == unique) {
		bpau->bpa_found = bpa;
		return HASHWALK_ABORT;
	}
	return HASHWALK_CONTINUE;
}

static int bgp_pbr_match_entry_walkcb(struct hash_backet *backet, void *arg)
{
	struct bgp_pbr_match_entry *bpme =
		(struct bgp_pbr_match_entry *)backet->data;
	struct bgp_pbr_match_entry_unique *bpmeu =
		(struct bgp_pbr_match_entry_unique *)arg;
	uint32_t unique = bpmeu->unique;

	if (bpme->unique == unique) {
		bpmeu->bpme_found = bpme;
		return HASHWALK_ABORT;
	}
	return HASHWALK_CONTINUE;
}

struct bgp_pbr_match_ipsetname {
	char *ipsetname;
	struct bgp_pbr_match *bpm_found;
};

static int bgp_pbr_match_pername_walkcb(struct hash_backet *backet, void *arg)
{
	struct bgp_pbr_match *bpm = (struct bgp_pbr_match *)backet->data;
	struct bgp_pbr_match_ipsetname *bpmi =
		(struct bgp_pbr_match_ipsetname *)arg;
	char *ipset_name = bpmi->ipsetname;

	if (!strncmp(ipset_name, bpm->ipset_name,
		     ZEBRA_IPSET_NAME_SIZE)) {
		bpmi->bpm_found = bpm;
		return HASHWALK_ABORT;
	}
	return HASHWALK_CONTINUE;
}

static int bgp_pbr_match_iptable_walkcb(struct hash_backet *backet, void *arg)
{
	struct bgp_pbr_match *bpm = (struct bgp_pbr_match *)backet->data;
	struct bgp_pbr_match_iptable_unique *bpmiu =
		(struct bgp_pbr_match_iptable_unique *)arg;
	uint32_t unique = bpmiu->unique;

	if (bpm->unique2 == unique) {
		bpmiu->bpm_found = bpm;
		return HASHWALK_ABORT;
	}
	return HASHWALK_CONTINUE;
}

struct bgp_pbr_match_unique {
	uint32_t unique;
	struct bgp_pbr_match *bpm_found;
};

static int bgp_pbr_match_walkcb(struct hash_backet *backet, void *arg)
{
	struct bgp_pbr_match *bpm = (struct bgp_pbr_match *)backet->data;
	struct bgp_pbr_match_unique *bpmu = (struct bgp_pbr_match_unique *)
		arg;
	uint32_t unique = bpmu->unique;

	if (bpm->unique == unique) {
		bpmu->bpm_found = bpm;
		return HASHWALK_ABORT;
	}
	return HASHWALK_CONTINUE;
}

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
		if (BGP_DEBUG(pbr, PBR)) {
			bgp_pbr_print_policy_route(api);
			zlog_debug("BGP: some SET actions not supported by Zebra. ignoring.");
		}
		return 0;
	}
	if (!(api->match_bitmask & PREFIX_SRC_PRESENT) &&
	    !(api->match_bitmask & PREFIX_DST_PRESENT)) {
		if (BGP_DEBUG(pbr, PBR)) {
			bgp_pbr_print_policy_route(api);
			zlog_debug("BGP: match actions without src"
				 " or dst address can not operate."
				 " ignoring.");
		}
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
				if (BGP_DEBUG(pbr, PBR_ERROR))
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
			if (BGP_DEBUG(pbr, PBR)) {
				bgp_pbr_print_policy_route(api);
				zlog_debug("%s: inconsistency:"
				     " no match for afi src and dst (%u/%u)",
				     __func__, afi, family2afi(dst->family));
			}
			return -1;
		}
	}
	return 0;
}

static void bgp_pbr_match_entry_free(void *arg)
{
	struct bgp_pbr_match_entry *bpme;

	bpme = (struct bgp_pbr_match_entry *)arg;

	if (bpme->installed) {
		bgp_send_pbr_ipset_entry_match(bpme, false);
		bpme->installed = false;
		bpme->backpointer = NULL;
	}
	XFREE(MTYPE_PBR_MATCH_ENTRY, bpme);
}

static void bgp_pbr_match_free(void *arg)
{
	struct bgp_pbr_match *bpm;

	bpm = (struct bgp_pbr_match *)arg;

	hash_clean(bpm->entry_hash, bgp_pbr_match_entry_free);

	if (hashcount(bpm->entry_hash) == 0) {
		/* delete iptable entry first */
		/* then delete ipset match */
		if (bpm->installed) {
			if (bpm->installed_in_iptable) {
				bgp_send_pbr_iptable(bpm->action,
						     bpm, false);
				bpm->installed_in_iptable = false;
				bpm->action->refcnt--;
			}
			bgp_send_pbr_ipset_match(bpm, false);
			bpm->installed = false;
			bpm->action = NULL;
		}
	}
	hash_free(bpm->entry_hash);

	XFREE(MTYPE_PBR_MATCH, bpm);
}

static void *bgp_pbr_match_alloc_intern(void *arg)
{
	struct bgp_pbr_match *bpm, *new;

	bpm = (struct bgp_pbr_match *)arg;

	new = XCALLOC(MTYPE_PBR_MATCH, sizeof(*new));
	memcpy(new, bpm, sizeof(*bpm));

	return new;
}

static void bgp_pbr_action_free(void *arg)
{
	struct bgp_pbr_action *bpa;

	bpa = (struct bgp_pbr_action *)arg;

	if (bpa->refcnt == 0) {
		if (bpa->installed && bpa->table_id != 0) {
			bgp_send_pbr_rule_action(bpa, false);
			bgp_zebra_announce_default(bpa->bgp, &(bpa->nh),
						   AFI_IP,
						   bpa->table_id,
						   false);
		}
	}
	XFREE(MTYPE_PBR_ACTION, bpa);
}

static void *bgp_pbr_action_alloc_intern(void *arg)
{
	struct bgp_pbr_action *bpa, *new;

	bpa = (struct bgp_pbr_action *)arg;

	new = XCALLOC(MTYPE_PBR_ACTION, sizeof(*new));

	memcpy(new, bpa, sizeof(*bpa));

	return new;
}

static void *bgp_pbr_match_entry_alloc_intern(void *arg)
{
	struct bgp_pbr_match_entry *bpme, *new;

	bpme = (struct bgp_pbr_match_entry *)arg;

	new = XCALLOC(MTYPE_PBR_MATCH_ENTRY, sizeof(*new));

	memcpy(new, bpme, sizeof(*bpme));

	return new;
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

struct bgp_pbr_action *bgp_pbr_action_rule_lookup(vrf_id_t vrf_id,
						  uint32_t unique)
{
	struct bgp *bgp = bgp_lookup_by_vrf_id(vrf_id);
	struct bgp_pbr_action_unique bpau;

	if (!bgp || unique == 0)
		return NULL;
	bpau.unique = unique;
	bpau.bpa_found = NULL;
	hash_walk(bgp->pbr_action_hash, bgp_pbr_action_walkcb, &bpau);
	return bpau.bpa_found;
}

struct bgp_pbr_match *bgp_pbr_match_ipset_lookup(vrf_id_t vrf_id,
						 uint32_t unique)
{
	struct bgp *bgp = bgp_lookup_by_vrf_id(vrf_id);
	struct bgp_pbr_match_unique bpmu;

	if (!bgp || unique == 0)
		return NULL;
	bpmu.unique = unique;
	bpmu.bpm_found = NULL;
	hash_walk(bgp->pbr_match_hash, bgp_pbr_match_walkcb, &bpmu);
	return bpmu.bpm_found;
}

struct bgp_pbr_match_entry *bgp_pbr_match_ipset_entry_lookup(vrf_id_t vrf_id,
						       char *ipset_name,
						       uint32_t unique)
{
	struct bgp *bgp = bgp_lookup_by_vrf_id(vrf_id);
	struct bgp_pbr_match_entry_unique bpmeu;
	struct bgp_pbr_match_ipsetname bpmi;

	if (!bgp || unique == 0)
		return NULL;
	bpmi.ipsetname = XCALLOC(MTYPE_TMP, ZEBRA_IPSET_NAME_SIZE);
	snprintf(bpmi.ipsetname, ZEBRA_IPSET_NAME_SIZE, "%s", ipset_name);
	bpmi.bpm_found = NULL;
	hash_walk(bgp->pbr_match_hash, bgp_pbr_match_pername_walkcb, &bpmi);
	XFREE(MTYPE_TMP, bpmi.ipsetname);
	if (!bpmi.bpm_found)
		return NULL;
	bpmeu.bpme_found = NULL;
	bpmeu.unique = unique;
	hash_walk(bpmi.bpm_found->entry_hash,
		  bgp_pbr_match_entry_walkcb, &bpmeu);
	return bpmeu.bpme_found;
}

struct bgp_pbr_match *bgp_pbr_match_iptable_lookup(vrf_id_t vrf_id,
						   uint32_t unique)
{
	struct bgp *bgp = bgp_lookup_by_vrf_id(vrf_id);
	struct bgp_pbr_match_iptable_unique bpmiu;

	if (!bgp || unique == 0)
		return NULL;
	bpmiu.unique = unique;
	bpmiu.bpm_found = NULL;
	hash_walk(bgp->pbr_match_hash, bgp_pbr_match_iptable_walkcb, &bpmiu);
	return bpmiu.bpm_found;
}

void bgp_pbr_cleanup(struct bgp *bgp)
{
	if (bgp->pbr_match_hash) {
		hash_clean(bgp->pbr_match_hash, bgp_pbr_match_free);
		hash_free(bgp->pbr_match_hash);
		bgp->pbr_match_hash = NULL;
	}
	if (bgp->pbr_action_hash) {
		hash_clean(bgp->pbr_action_hash, bgp_pbr_action_free);
		hash_free(bgp->pbr_action_hash);
		bgp->pbr_action_hash = NULL;
	}
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

static void bgp_pbr_flush_entry(struct bgp *bgp, struct bgp_pbr_action *bpa,
				struct bgp_pbr_match *bpm,
				struct bgp_pbr_match_entry *bpme)
{
	/* if bpme is null, bpm is also null
	 */
	if (bpme == NULL)
		return;
	/* ipset del entry */
	if (bpme->installed) {
		bgp_send_pbr_ipset_entry_match(bpme, false);
		bpme->installed = false;
		bpme->backpointer = NULL;
	}
	hash_release(bpm->entry_hash, bpme);
	if (hashcount(bpm->entry_hash) == 0) {
		/* delete iptable entry first */
		/* then delete ipset match */
		if (bpm->installed) {
			if (bpm->installed_in_iptable) {
				bgp_send_pbr_iptable(bpm->action,
						     bpm, false);
				bpm->installed_in_iptable = false;
				bpm->action->refcnt--;
			}
			bgp_send_pbr_ipset_match(bpm, false);
			bpm->installed = false;
			bpm->action = NULL;
		}
		hash_release(bgp->pbr_match_hash, bpm);
		/* XXX release pbr_match_action if not used
		 * note that drop does not need to call send_pbr_action
		 */
	}
	if (bpa->refcnt == 0) {
		if (bpa->installed && bpa->table_id != 0) {
			bgp_send_pbr_rule_action(bpa, false);
			bgp_zebra_announce_default(bpa->bgp, &(bpa->nh),
						   AFI_IP,
						   bpa->table_id,
						   false);
		}
	}
}

struct bgp_pbr_match_entry_remain {
	struct bgp_pbr_match_entry *bpme_to_match;
	struct bgp_pbr_match_entry *bpme_found;
};

static int bgp_pbr_get_remaining_entry(struct hash_backet *backet, void *arg)
{
	struct bgp_pbr_match *bpm = (struct bgp_pbr_match *)backet->data;
	struct bgp_pbr_match_entry_remain *bpmer =
		(struct bgp_pbr_match_entry_remain *)arg;
	struct bgp_pbr_match *bpm_temp;
	struct bgp_pbr_match_entry *bpme = bpmer->bpme_to_match;

	if (!bpme->backpointer ||
	    bpm == bpme->backpointer ||
	    bpme->backpointer->action == bpm->action)
		return HASHWALK_CONTINUE;
	/* ensure bpm other characteristics are equal */
	bpm_temp = bpme->backpointer;
	if (bpm_temp->vrf_id != bpm->vrf_id ||
	    bpm_temp->type != bpm->type ||
	    bpm_temp->flags != bpm->flags)
		return HASHWALK_CONTINUE;

	/* look for remaining bpme */
	bpmer->bpme_found = hash_lookup(bpm->entry_hash, bpme);
	if (!bpmer->bpme_found)
		return HASHWALK_CONTINUE;
	return HASHWALK_ABORT;
}

static void bgp_pbr_policyroute_remove_from_zebra(struct bgp *bgp,
						  struct bgp_info *binfo,
						  vrf_id_t vrf_id,
						  struct prefix *src,
						  struct prefix *dst)
{
	struct bgp_pbr_match temp;
	struct bgp_pbr_match_entry temp2;
	struct bgp_pbr_match *bpm;
	struct bgp_pbr_match_entry *bpme;
	struct bgp_pbr_match_entry_remain bpmer;

	/* as we don't know information from EC
	 * look for bpm that have the bpm
	 * with vrf_id characteristics
	 */
	memset(&temp2, 0, sizeof(temp2));
	memset(&temp, 0, sizeof(temp));
	if (src) {
		temp.flags |= MATCH_IP_SRC_SET;
		prefix_copy(&temp2.src, src);
	} else
		temp2.src.family = AF_INET;
	if (dst) {
		temp.flags |= MATCH_IP_DST_SET;
		prefix_copy(&temp2.dst, dst);
	} else
		temp2.dst.family = AF_INET;

	if (src == NULL || dst == NULL)
		temp.type = IPSET_NET;
	else
		temp.type = IPSET_NET_NET;
	if (vrf_id == VRF_UNKNOWN) /* XXX case BGP destroy */
		temp.vrf_id = 0;
	else
		temp.vrf_id = vrf_id;
	bpme = &temp2;
	bpm = &temp;
	bpme->backpointer = bpm;
	/* right now, a previous entry may already exist
	 * flush previous entry if necessary
	 */
	bpmer.bpme_to_match = bpme;
	bpmer.bpme_found = NULL;
	hash_walk(bgp->pbr_match_hash, bgp_pbr_get_remaining_entry, &bpmer);
	if (bpmer.bpme_found) {
		static struct bgp_pbr_match *local_bpm;
		static struct bgp_pbr_action *local_bpa;

		local_bpm = bpmer.bpme_found->backpointer;
		local_bpa = local_bpm->action;
		bgp_pbr_flush_entry(bgp, local_bpa,
				    local_bpm, bpmer.bpme_found);
	}
}

static void bgp_pbr_policyroute_add_to_zebra(struct bgp *bgp,
					     struct bgp_info *binfo,
					     vrf_id_t vrf_id,
					     struct prefix *src,
					     struct prefix *dst,
					     struct nexthop *nh,
					     float *rate)
{
	struct bgp_pbr_match temp;
	struct bgp_pbr_match_entry temp2;
	struct bgp_pbr_match *bpm;
	struct bgp_pbr_match_entry *bpme = NULL;
	struct bgp_pbr_action temp3;
	struct bgp_pbr_action *bpa = NULL;
	struct bgp_pbr_match_entry_remain bpmer;

	/* look for bpa first */
	memset(&temp3, 0, sizeof(temp3));
	if (rate)
		temp3.rate = *rate;
	if (nh)
		memcpy(&temp3.nh, nh, sizeof(struct nexthop));
	temp3.vrf_id = vrf_id;
	bpa = hash_get(bgp->pbr_action_hash, &temp3,
		       bgp_pbr_action_alloc_intern);

	if (bpa->fwmark == 0) {
		/* drop is handled by iptable */
		if (nh && nh->type == NEXTHOP_TYPE_BLACKHOLE) {
			bpa->table_id = 0;
			bpa->installed = true;
		} else {
			bpa->fwmark = bgp_zebra_tm_get_id();
			bpa->table_id = bpa->fwmark;
			bpa->installed = false;
		}
		bpa->bgp = bgp;
		bpa->unique = ++bgp_pbr_action_counter_unique;
		/* 0 value is forbidden */
		bpa->install_in_progress = false;
	}

	/* then look for bpm */
	memset(&temp, 0, sizeof(temp));
	if (src == NULL || dst == NULL)
		temp.type = IPSET_NET;
	else
		temp.type = IPSET_NET_NET;
	temp.vrf_id = vrf_id;
	if (src)
		temp.flags |= MATCH_IP_SRC_SET;
	if (dst)
		temp.flags |= MATCH_IP_DST_SET;
	temp.action = bpa;
	bpm = hash_get(bgp->pbr_match_hash, &temp,
		       bgp_pbr_match_alloc_intern);

	/* new, then self allocate ipset_name and unique */
	if (bpm && bpm->unique == 0) {
		bpm->unique = ++bgp_pbr_match_counter_unique;
		/* 0 value is forbidden */
		sprintf(bpm->ipset_name, "match%p", bpm);
		bpm->entry_hash = hash_create_size(8,
				   bgp_pbr_match_entry_hash_key,
				   bgp_pbr_match_entry_hash_equal,
				   "Match Entry Hash");
		bpm->installed = false;

		/* unique2 should be updated too */
		bpm->unique2 = ++bgp_pbr_match_iptable_counter_unique;
		bpm->installed_in_iptable = false;
		bpm->install_in_progress = false;
		bpm->install_iptable_in_progress = false;
	}

	memset(&temp2, 0, sizeof(temp2));
	if (src)
		prefix_copy(&temp2.src, src);
	else
		temp2.src.family = AF_INET;
	if (dst)
		prefix_copy(&temp2.dst, dst);
	else
		temp2.dst.family = AF_INET;
	if (bpm)
		bpme = hash_get(bpm->entry_hash, &temp2,
			bgp_pbr_match_entry_alloc_intern);
	if (bpme && bpme->unique == 0) {
		bpme->unique = ++bgp_pbr_match_entry_counter_unique;
		/* 0 value is forbidden */
		bpme->backpointer = bpm;
		bpme->installed = false;
		bpme->install_in_progress = false;
	}

	/* BGP FS: append entry to zebra
	 * - policies are not routing entries and as such
	 * route replace semantics don't necessarily follow
	 * through to policy entries
	 * - because of that, not all policing information will be stored
	 * into zebra. and non selected policies will be suppressed from zebra
	 * - as consequence, in order to bring consistency
	 * a policy will be added, then ifan ecmp policy exists,
	 * it will be suppressed subsequently
	 */
	/* ip rule add */
	if (!bpa->installed) {
		bgp_send_pbr_rule_action(bpa, true);
		bgp_zebra_announce_default(bgp, nh,
					   AFI_IP, bpa->table_id, true);
	}

	/* ipset create */
	if (bpm && !bpm->installed)
		bgp_send_pbr_ipset_match(bpm, true);
	/* ipset add */
	if (bpme && !bpme->installed)
		bgp_send_pbr_ipset_entry_match(bpme, true);

	/* iptables */
	if (bpm && !bpm->installed_in_iptable)
		bgp_send_pbr_iptable(bpa, bpm, true);

	/* A previous entry may already exist
	 * flush previous entry if necessary
	 */
	bpmer.bpme_to_match = bpme;
	bpmer.bpme_found = NULL;
	hash_walk(bgp->pbr_match_hash, bgp_pbr_get_remaining_entry, &bpmer);
	if (bpmer.bpme_found) {
		static struct bgp_pbr_match *local_bpm;
		static struct bgp_pbr_action *local_bpa;

		local_bpm = bpmer.bpme_found->backpointer;
		local_bpa = local_bpm->action;
		bgp_pbr_flush_entry(bgp, local_bpa,
				    local_bpm, bpmer.bpme_found);
	}


}

static void bgp_pbr_handle_entry(struct bgp *bgp,
				struct bgp_info *binfo,
				struct bgp_pbr_entry_main *api,
				bool add)
{
	struct nexthop nh;
	int i = 0;
	int continue_loop = 1;
	float rate = 0;
	struct prefix *src = NULL, *dst = NULL;

	if (api->match_bitmask & PREFIX_SRC_PRESENT)
		src = &api->src_prefix;
	if (api->match_bitmask & PREFIX_DST_PRESENT)
		dst = &api->dst_prefix;
	memset(&nh, 0, sizeof(struct nexthop));
	nh.vrf_id = VRF_UNKNOWN;

	if (!add)
		return bgp_pbr_policyroute_remove_from_zebra(bgp, binfo,
					     api->vrf_id, src, dst);
	/* no action for add = true */
	for (i = 0; i < api->action_num; i++) {
		switch (api->actions[i].action) {
		case ACTION_TRAFFICRATE:
			/* drop packet */
			if (api->actions[i].u.r.rate == 0) {
				nh.vrf_id = api->vrf_id;
				nh.type = NEXTHOP_TYPE_BLACKHOLE;
				bgp_pbr_policyroute_add_to_zebra(bgp, binfo,
						    api->vrf_id, src, dst,
						    &nh, &rate);
			} else {
				/* update rate. can be reentrant */
				rate = api->actions[i].u.r.rate;
				if (BGP_DEBUG(pbr, PBR)) {
					bgp_pbr_print_policy_route(api);
					zlog_warn("PBR: ignoring Set action rate %f",
						  api->actions[i].u.r.rate);
				}
			}
			break;
		case ACTION_TRAFFIC_ACTION:
			if (api->actions[i].u.za.filter
			    & TRAFFIC_ACTION_SAMPLE) {
				if (BGP_DEBUG(pbr, PBR)) {
					bgp_pbr_print_policy_route(api);
					zlog_warn("PBR: Sample action Ignored");
				}
			}
#if 0
			if (api->actions[i].u.za.filter
			    & TRAFFIC_ACTION_DISTRIBUTE) {
				if (BGP_DEBUG(pbr, PBR)) {
					bgp_pbr_print_policy_route(api);
					zlog_warn("PBR: Distribute action Applies");
				}
				continue_loop = 0;
				/* continue forwarding entry as before
				 * no action
				 */
			}
#endif /* XXX to confirm behaviour of traffic action. for now , ignore */
			/* terminate action: run other filters
			 */
			break;
		case ACTION_REDIRECT_IP:
			nh.type = NEXTHOP_TYPE_IPV4;
			nh.gate.ipv4.s_addr =
				api->actions[i].u.zr.redirect_ip_v4.s_addr;
			nh.vrf_id = api->vrf_id;
			bgp_pbr_policyroute_add_to_zebra(bgp, binfo,
							    api->vrf_id,
							    src, dst,
							    &nh, &rate);
			/* XXX combination with REDIRECT_VRF
			 * + REDIRECT_NH_IP not done
			 */
			continue_loop = 0;
			break;
		case ACTION_REDIRECT:
			nh.vrf_id = api->actions[i].u.redirect_vrf;
			nh.type = NEXTHOP_TYPE_IPV4;
			bgp_pbr_policyroute_add_to_zebra(bgp, binfo,
							 api->vrf_id,
							 src, dst,
							 &nh, &rate);
			continue_loop = 0;
			break;
		case ACTION_MARKING:
			if (BGP_DEBUG(pbr, PBR)) {
				bgp_pbr_print_policy_route(api);
				zlog_warn("PBR: Set DSCP %u Ignored",
					  api->actions[i].u.marking_dscp);
			}
			break;
		default:
			break;
		}
		if (continue_loop == 0)
			break;
	}
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
		if (BGP_DEBUG(pbr, PBR_ERROR))
			zlog_err("%s: cancel updating entry in bgp pbr",
				 __func__);
		return;
	}
	bgp_pbr_handle_entry(bgp, info, &api, nlri_update);
}
