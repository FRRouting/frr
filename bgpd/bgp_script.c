// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP scripting foo
 * Copyright (C) 2020  NVIDIA Corporation
 * Quentin Young
 */

#include <zebra.h>

#ifdef HAVE_SCRIPTING

#include "bgpd.h"
#include "bgp_script.h"
#include "bgp_debug.h"
#include "bgp_aspath.h"
#include "bgp_attr.h"
#include "bgp_community.h"
#include "bgp_ecommunity.h"
#include "bgp_lcommunity.h"
#include "bgp_attr_evpn.h"
#include "bgp_route.h"
#include "frratomic.h"
#include "frrscript.h"
#include "ipaddr.h"
#include "log.h"

#if CONFDATE > 20280801
CPP_NOTICE("This code is no longer considered Experimental and should be converted to set in stone")
#endif

/* Encode an optional integer attr: nil when the presence flag is clear. */
static void lua_push_optional_uint(lua_State *L, const struct attr *attr,
				   uint64_t flagbit, uint64_t value,
				   const char *key)
{
	if (CHECK_FLAG(attr->flag, flagbit))
		lua_pushinteger(L, (lua_Integer)value);
	else
		lua_pushnil(L);
	lua_setfield(L, -2, key);
}

/*
 * Decode optional integer. nil/absent clears the flag and zeroes the field.
 * Returns true if the value is present (and *out is set).
 */
static bool lua_decode_optional_uint(lua_State *L, int idx, const char *key, struct attr *attr,
				     uint64_t flagbit, uint64_t *out)
{
	lua_getfield(L, idx, key);
	if (lua_isnil(L, -1)) {
		UNSET_FLAG(attr->flag, flagbit);
		*out = 0;
		lua_pop(L, 1);
		return false;
	}
	*out = (uint64_t)lua_tointeger(L, -1);
	SET_FLAG(attr->flag, flagbit);
	lua_pop(L, 1);
	return true;
}

/* Replace aspath on a working attr copy without freeing a shared original. */
static void lua_decode_aspath_field(lua_State *L, int idx, struct attr *attr)
{
	struct aspath *new_aspath = NULL;
	const char *str;

	lua_getfield(L, idx, "aspath");
	if (lua_isnil(L, -1)) {
		attr->aspath = NULL;
		bgp_attr_unset(attr, BGP_ATTR_AS_PATH);
		lua_pop(L, 1);
		return;
	}

	str = lua_tostring(L, -1);
	if (str && attr->aspath && attr->aspath->str
	    && strcmp(attr->aspath->str, str) == 0) {
		lua_pop(L, 1);
		return;
	}

	if (str && *str)
		new_aspath = aspath_str2aspath(str,
					       bgp_get_asnotation(NULL));
	if (!new_aspath && str && *str) {
		lua_pop(L, 1);
		return;
	}

	/*
	 * Working attrs are shallow-copied from path->attr; do not free the
	 * previous pointer here — it may still be referenced by the original.
	 * Ownership is resolved in bgp_attr_script_apply / discard.
	 */
	attr->aspath = new_aspath;
	if (new_aspath)
		SET_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_AS_PATH));
	else
		bgp_attr_unset(attr, BGP_ATTR_AS_PATH);
	lua_pop(L, 1);
}


static void lua_push_community_field(lua_State *L, struct community *com,
				     const char *key)
{
	if (com) {
		char *str = community_str(com, false, false);

		lua_pushstring(L, str ? str : "");
	} else
		lua_pushnil(L);
	lua_setfield(L, -2, key);
}

static void lua_decode_community_field(lua_State *L, int idx, struct attr *attr)
{
	struct community *new_com = NULL;
	struct community *old;
	const char *str;

	lua_getfield(L, idx, "community");
	if (lua_isnil(L, -1)) {
		bgp_attr_set_community(attr, NULL);
		lua_pop(L, 1);
		return;
	}

	str = lua_tostring(L, -1);
	old = bgp_attr_get_community(attr);
	if (str && old) {
		char *cur = community_str(old, false, false);

		if (cur && strcmp(cur, str) == 0) {
			lua_pop(L, 1);
			return;
		}
	}

	if (str && *str)
		new_com = community_str2com(str);
	if (!new_com && str && *str) {
		lua_pop(L, 1);
		return;
	}

	/* Do not free old pointer; may be shared with original attr. */
	bgp_attr_set_community(attr, new_com);
	lua_pop(L, 1);
}

static void bgp_attr_script_apply_community(struct attr *dst, struct attr *src)
{
	struct community *old = bgp_attr_get_community(dst);
	struct community *new = bgp_attr_get_community(src);

	if (old == new)
		return;

	if (old && old->refcnt == 0)
		community_free(&old);

	bgp_attr_set_community(dst, new);
	bgp_attr_set_community(src, NULL);
}


static void lua_push_lcommunity_field(lua_State *L, struct lcommunity *lcom,
				      const char *key)
{
	if (lcom) {
		char *str = lcommunity_str(lcom, false, false);

		lua_pushstring(L, str ? str : "");
	} else
		lua_pushnil(L);
	lua_setfield(L, -2, key);
}

static void lua_decode_lcommunity_field(lua_State *L, int idx, struct attr *attr)
{
	struct lcommunity *new_lcom = NULL;
	struct lcommunity *old;
	const char *str;

	lua_getfield(L, idx, "large_community");
	if (lua_isnil(L, -1)) {
		bgp_attr_set_lcommunity(attr, NULL);
		lua_pop(L, 1);
		return;
	}

	str = lua_tostring(L, -1);
	old = bgp_attr_get_lcommunity(attr);
	if (str && old) {
		char *cur = lcommunity_str(old, false, false);

		if (cur && strcmp(cur, str) == 0) {
			lua_pop(L, 1);
			return;
		}
	}

	if (str && *str)
		new_lcom = lcommunity_str2com(str);
	if (!new_lcom && str && *str) {
		lua_pop(L, 1);
		return;
	}

	bgp_attr_set_lcommunity(attr, new_lcom);
	lua_pop(L, 1);
}

static void bgp_attr_script_apply_lcommunity(struct attr *dst, struct attr *src)
{
	struct lcommunity *old = bgp_attr_get_lcommunity(dst);
	struct lcommunity *new = bgp_attr_get_lcommunity(src);

	if (old == new)
		return;

	if (old && old->refcnt == 0)
		lcommunity_free(&old);

	bgp_attr_set_lcommunity(dst, new);
	bgp_attr_set_lcommunity(src, NULL);
}


static void lua_push_ecommunity_field(lua_State *L, struct ecommunity *ecom,
				      const char *key)
{
	/*
	 * Use community-list form ("rt 100:1") so ecommunity_str2com(..., 0, 1)
	 * can round-trip. ecommunity_str() is DISPLAY form ("RT:100:1"), which
	 * the parser does not accept.
	 */
	if (ecom) {
		char *str = ecommunity_ecom2str(ecom,
						ECOMMUNITY_FORMAT_COMMUNITY_LIST,
						0);

		lua_pushstring(L, str ? str : "");
		XFREE(MTYPE_ECOMMUNITY_STR, str);
	} else
		lua_pushnil(L);
	lua_setfield(L, -2, key);
}

static void lua_decode_ecommunity_field(lua_State *L, int idx, struct attr *attr)
{
	struct ecommunity *new_ecom = NULL;
	struct ecommunity *old;
	const char *str;

	lua_getfield(L, idx, "extcommunity");
	if (lua_isnil(L, -1)) {
		bgp_attr_set_ecommunity(attr, NULL);
		lua_pop(L, 1);
		return;
	}

	str = lua_tostring(L, -1);
	old = bgp_attr_get_ecommunity(attr);
	if (str && old) {
		char *cur = ecommunity_ecom2str(old,
						ECOMMUNITY_FORMAT_COMMUNITY_LIST,
						0);
		int same = cur && strcmp(cur, str) == 0;

		XFREE(MTYPE_ECOMMUNITY_STR, cur);
		if (same) {
			lua_pop(L, 1);
			return;
		}
	}

	if (str && *str)
		new_ecom = ecommunity_str2com(str, 0, 1);
	if (!new_ecom && str && *str) {
		lua_pop(L, 1);
		return;
	}

	bgp_attr_set_ecommunity(attr, new_ecom);
	lua_pop(L, 1);
}

static void bgp_attr_script_apply_ecommunity(struct attr *dst, struct attr *src)
{
	struct ecommunity *old = bgp_attr_get_ecommunity(dst);
	struct ecommunity *new = bgp_attr_get_ecommunity(src);

	if (old == new)
		return;

	if (old && old->refcnt == 0)
		ecommunity_free(&old);

	bgp_attr_set_ecommunity(dst, new);
	bgp_attr_set_ecommunity(src, NULL);
}


static void lua_decode_ipv6_ecommunity_field(lua_State *L, int idx,
					     struct attr *attr)
{
	struct ecommunity *new_ecom = NULL;
	struct ecommunity *old;
	const char *str;

	lua_getfield(L, idx, "ipv6_extcommunity");
	if (lua_isnil(L, -1)) {
		bgp_attr_set_ipv6_ecommunity(attr, NULL);
		lua_pop(L, 1);
		return;
	}

	str = lua_tostring(L, -1);
	old = bgp_attr_get_ipv6_ecommunity(attr);
	if (str && old) {
		char *cur = ecommunity_ecom2str(old,
						ECOMMUNITY_FORMAT_COMMUNITY_LIST,
						0);
		int same = cur && strcmp(cur, str) == 0;

		XFREE(MTYPE_ECOMMUNITY_STR, cur);
		if (same) {
			lua_pop(L, 1);
			return;
		}
	}

	if (str && *str)
		new_ecom = ecommunity_str2com_ipv6(str, 0, 1);
	if (!new_ecom && str && *str) {
		lua_pop(L, 1);
		return;
	}

	bgp_attr_set_ipv6_ecommunity(attr, new_ecom);
	lua_pop(L, 1);
}

static void bgp_attr_script_apply_ipv6_ecommunity(struct attr *dst,
						  struct attr *src)
{
	struct ecommunity *old = bgp_attr_get_ipv6_ecommunity(dst);
	struct ecommunity *new = bgp_attr_get_ipv6_ecommunity(src);

	if (old == new)
		return;

	if (old && old->refcnt == 0)
		ecommunity_free(&old);

	bgp_attr_set_ipv6_ecommunity(dst, new);
	bgp_attr_set_ipv6_ecommunity(src, NULL);
}

static void bgp_attr_script_apply_aspath(struct attr *dst, struct attr *src)
{
	if (dst->aspath == src->aspath)
		return;

	if (dst->aspath && dst->aspath->refcnt == 0)
		aspath_free(dst->aspath);

	dst->aspath = src->aspath;
	src->aspath = NULL;

	if (dst->aspath)
		SET_FLAG(dst->flag, ATTR_FLAG_BIT(BGP_ATTR_AS_PATH));
	else
		bgp_attr_unset(dst, BGP_ATTR_AS_PATH);
}

static void bgp_attr_script_apply_evpn(struct attr *dst, struct attr *src)
{
	struct bgp_route_evpn *old = bgp_attr_get_evpn_overlay(dst);
	struct bgp_route_evpn *new = bgp_attr_get_evpn_overlay(src);

	dst->evpn_flags = src->evpn_flags;

	if (old == new)
		return;

	if (old && old->refcnt == 0)
		evpn_overlay_free(old);

	bgp_attr_set_evpn_overlay(dst, new);
	bgp_attr_set_evpn_overlay(src, NULL);
}

void bgp_attr_script_apply(struct attr *dst, struct attr *src)
{
	/* metric / MED */
	if (CHECK_FLAG(src->flag, ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC)))
		bgp_attr_set_med(dst, src->med);
	else {
		bgp_attr_unset(dst, BGP_ATTR_MULTI_EXIT_DISC);
		dst->med = 0;
	}

	/* local preference */
	if (CHECK_FLAG(src->flag, ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF))) {
		SET_FLAG(dst->flag, ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF));
		dst->local_pref = src->local_pref;
	} else {
		bgp_attr_unset(dst, BGP_ATTR_LOCAL_PREF);
		dst->local_pref = 0;
	}

	/* nexthop ifindexes (flat ifindex kept for compatibility) */
	dst->nh_ifindex = src->nh_ifindex;
	dst->nh_lla_ifindex = src->nh_lla_ifindex;
	dst->nh_flags = src->nh_flags;

	if (CHECK_FLAG(src->flag, ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP))) {
		dst->nexthop = src->nexthop;
		SET_FLAG(dst->flag, ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP));
	} else {
		memset(&dst->nexthop, 0, sizeof(dst->nexthop));
		bgp_attr_unset(dst, BGP_ATTR_NEXT_HOP);
	}
	dst->mp_nexthop_global = src->mp_nexthop_global;
	dst->mp_nexthop_local = src->mp_nexthop_local;
	dst->mp_nexthop_global_in = src->mp_nexthop_global_in;
	dst->mp_nexthop_len = src->mp_nexthop_len;
	/* Full rmap_change_flags from script (peer-address, unchanged, etc.) */
	dst->rmap_change_flags = src->rmap_change_flags;

	if (CHECK_FLAG(src->flag, ATTR_FLAG_BIT(BGP_ATTR_AGGREGATOR))) {
		dst->aggregator_as = src->aggregator_as;
		dst->aggregator_addr = src->aggregator_addr;
		SET_FLAG(dst->flag, ATTR_FLAG_BIT(BGP_ATTR_AGGREGATOR));
	} else {
		dst->aggregator_as = 0;
		memset(&dst->aggregator_addr, 0, sizeof(dst->aggregator_addr));
		bgp_attr_unset(dst, BGP_ATTR_AGGREGATOR);
	}

	if (CHECK_FLAG(src->flag, ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID))) {
		dst->originator_id = src->originator_id;
		SET_FLAG(dst->flag, ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID));
	} else {
		memset(&dst->originator_id, 0, sizeof(dst->originator_id));
		bgp_attr_unset(dst, BGP_ATTR_ORIGINATOR_ID);
	}

	dst->origin = src->origin;
	dst->weight = src->weight;
	dst->distance = src->distance;
	dst->tag = src->tag;
	dst->rmap_table_id = src->rmap_table_id;

	if (CHECK_FLAG(src->flag, ATTR_FLAG_BIT(BGP_ATTR_PREFIX_SID))) {
		dst->label_index = src->label_index;
		SET_FLAG(dst->flag, ATTR_FLAG_BIT(BGP_ATTR_PREFIX_SID));
	} else {
		dst->label_index = 0;
		bgp_attr_unset(dst, BGP_ATTR_PREFIX_SID);
	}

	if (CHECK_FLAG(src->flag, ATTR_FLAG_BIT(BGP_ATTR_AIGP)))
		bgp_attr_set_aigp_metric(dst, bgp_attr_get_aigp_metric(src));
	else
		bgp_attr_unset_aigp_metric(dst);

	if (CHECK_FLAG(src->flag, ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE)))
		SET_FLAG(dst->flag, ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE));
	else
		bgp_attr_unset(dst, BGP_ATTR_ATOMIC_AGGREGATE);

	bgp_attr_script_apply_community(dst, src);
	bgp_attr_script_apply_lcommunity(dst, src);
	bgp_attr_script_apply_ecommunity(dst, src);
	bgp_attr_script_apply_ipv6_ecommunity(dst, src);
	bgp_attr_script_apply_evpn(dst, src);

	bgp_attr_script_apply_aspath(dst, src);
}

void bgp_attr_script_discard(struct attr *working, const struct attr *orig)
{
	struct community *com = bgp_attr_get_community(working);
	struct community *ocom = bgp_attr_get_community(orig);

	if (working->aspath && working->aspath != orig->aspath
	    && working->aspath->refcnt == 0)
		aspath_free(working->aspath);
	working->aspath = NULL;

	if (com && com != ocom && com->refcnt == 0)
		community_free(&com);
	bgp_attr_set_community(working, NULL);

	{
		struct lcommunity *lcom = bgp_attr_get_lcommunity(working);
		struct lcommunity *olcom = bgp_attr_get_lcommunity(orig);

		if (lcom && lcom != olcom && lcom->refcnt == 0)
			lcommunity_free(&lcom);
		bgp_attr_set_lcommunity(working, NULL);
	}

	{
		struct ecommunity *ecom = bgp_attr_get_ecommunity(working);
		struct ecommunity *oecom = bgp_attr_get_ecommunity(orig);

		if (ecom && ecom != oecom && ecom->refcnt == 0)
			ecommunity_free(&ecom);
		bgp_attr_set_ecommunity(working, NULL);
	}

	{
		struct ecommunity *ecom = bgp_attr_get_ipv6_ecommunity(working);
		struct ecommunity *oecom = bgp_attr_get_ipv6_ecommunity(orig);

		if (ecom && ecom != oecom && ecom->refcnt == 0)
			ecommunity_free(&ecom);
		bgp_attr_set_ipv6_ecommunity(working, NULL);
	}

	{
		struct bgp_route_evpn *bre = bgp_attr_get_evpn_overlay(working);
		struct bgp_route_evpn *obre = bgp_attr_get_evpn_overlay(orig);

		if (bre && bre != obre && bre->refcnt == 0)
			evpn_overlay_free(bre);
		bgp_attr_set_evpn_overlay(working, NULL);
	}
}


static void lua_push_nexthop_table(lua_State *L, const struct attr *attr)
{
	char buf[INET6_ADDRSTRLEN];

	lua_newtable(L);

	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP))) {
		inet_ntop(AF_INET, &attr->nexthop, buf, sizeof(buf));
		lua_pushstring(L, buf);
	} else
		lua_pushnil(L);
	lua_setfield(L, -2, "ipv4");

	if (attr->mp_nexthop_len == BGP_ATTR_NHLEN_IPV4
	    || attr->mp_nexthop_len == BGP_ATTR_NHLEN_VPNV4) {
		inet_ntop(AF_INET, &attr->mp_nexthop_global_in, buf, sizeof(buf));
		lua_pushstring(L, buf);
	} else
		lua_pushnil(L);
	lua_setfield(L, -2, "vpnv4");

	if (attr->mp_nexthop_len == BGP_ATTR_NHLEN_IPV6_GLOBAL
	    || attr->mp_nexthop_len == BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL
	    || attr->mp_nexthop_len == BGP_ATTR_NHLEN_VPNV6_GLOBAL
	    || attr->mp_nexthop_len == BGP_ATTR_NHLEN_VPNV6_GLOBAL_AND_LL) {
		inet_ntop(AF_INET6, &attr->mp_nexthop_global, buf, sizeof(buf));
		lua_pushstring(L, buf);
	} else
		lua_pushnil(L);
	lua_setfield(L, -2, "ipv6_global");

	if (attr->mp_nexthop_len == BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL
	    || attr->mp_nexthop_len == BGP_ATTR_NHLEN_VPNV6_GLOBAL_AND_LL) {
		inet_ntop(AF_INET6, &attr->mp_nexthop_local, buf, sizeof(buf));
		lua_pushstring(L, buf);
	} else
		lua_pushnil(L);
	lua_setfield(L, -2, "ipv6_local");

	lua_pushinteger(L, attr->mp_nexthop_len);
	lua_setfield(L, -2, "mp_len");

	lua_pushinteger(L, attr->nh_ifindex);
	lua_setfield(L, -2, "ifindex");
	lua_pushinteger(L, attr->nh_lla_ifindex);
	lua_setfield(L, -2, "lla_ifindex");

	lua_pushboolean(L, CHECK_FLAG(attr->nh_flags,
				      BGP_ATTR_NH_MP_PREFER_GLOBAL));
	lua_setfield(L, -2, "prefer_global");
}

/*
 * orig_nh_ifindex is attr->nh_ifindex as it was before any decoding of
 * this attributes table began (i.e. what was pushed to Lua as both the
 * flat "ifindex" key and "nexthop.ifindex"). It is used to tell which of
 * the two redundant keys the script actually changed, since both are
 * always present (never nil) on the pushed table.
 */
static void lua_decode_nexthop_table(lua_State *L, int idx, struct attr *attr,
				     ifindex_t orig_nh_ifindex)
{
	struct in_addr old_ipv4 = attr->nexthop;
	struct in_addr old_vpnv4 = attr->mp_nexthop_global_in;
	struct in6_addr old_v6g = attr->mp_nexthop_global;
	struct in6_addr old_v6l = attr->mp_nexthop_local;
	uint8_t old_nh_flags = attr->nh_flags;
	bool had_ipv4 = CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP));

	lua_getfield(L, idx, "nexthop");
	if (lua_isnil(L, -1) || !lua_istable(L, -1)) {
		lua_pop(L, 1);
		return;
	}

	lua_getfield(L, -1, "ipv4");
	if (lua_isnil(L, -1)) {
		if (had_ipv4)
			SET_FLAG(attr->rmap_change_flags,
				 BATTR_RMAP_IPV4_NHOP_CHANGED);
		bgp_attr_unset(attr, BGP_ATTR_NEXT_HOP);
		memset(&attr->nexthop, 0, sizeof(attr->nexthop));
	} else {
		const char *str = lua_tostring(L, -1);

		if (str && inet_pton(AF_INET, str, &attr->nexthop) == 1) {
			SET_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP));
			if (!had_ipv4 || old_ipv4.s_addr != attr->nexthop.s_addr)
				SET_FLAG(attr->rmap_change_flags,
					 BATTR_RMAP_IPV4_NHOP_CHANGED);
		}
	}
	lua_pop(L, 1); /* ipv4 */

	lua_getfield(L, -1, "vpnv4");
	if (!lua_isnil(L, -1)) {
		const char *str = lua_tostring(L, -1);

		if (str && inet_pton(AF_INET, str, &attr->mp_nexthop_global_in)
			    == 1) {
			attr->mp_nexthop_len = BGP_ATTR_NHLEN_VPNV4;
			if (old_vpnv4.s_addr != attr->mp_nexthop_global_in.s_addr)
				SET_FLAG(attr->rmap_change_flags,
					 BATTR_RMAP_VPNV4_NHOP_CHANGED);
		}
	} else
		memset(&attr->mp_nexthop_global_in, 0,
		       sizeof(attr->mp_nexthop_global_in));
	lua_pop(L, 1);

	lua_getfield(L, -1, "ipv6_global");
	if (!lua_isnil(L, -1)) {
		const char *str = lua_tostring(L, -1);

		if (str && inet_pton(AF_INET6, str, &attr->mp_nexthop_global)
			    == 1) {
			if (!attr->mp_nexthop_len)
				attr->mp_nexthop_len = BGP_ATTR_NHLEN_IPV6_GLOBAL;
			if (memcmp(&old_v6g, &attr->mp_nexthop_global,
				   sizeof(old_v6g)))
				SET_FLAG(attr->rmap_change_flags,
					 BATTR_RMAP_IPV6_GLOBAL_NHOP_CHANGED);
		}
	} else
		memset(&attr->mp_nexthop_global, 0,
		       sizeof(attr->mp_nexthop_global));
	lua_pop(L, 1);

	lua_getfield(L, -1, "ipv6_local");
	if (!lua_isnil(L, -1)) {
		const char *str = lua_tostring(L, -1);

		if (str && inet_pton(AF_INET6, str, &attr->mp_nexthop_local)
			    == 1) {
			attr->mp_nexthop_len = BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL;
			if (memcmp(&old_v6l, &attr->mp_nexthop_local,
				   sizeof(old_v6l)))
				SET_FLAG(attr->rmap_change_flags,
					 BATTR_RMAP_IPV6_LL_NHOP_CHANGED);
		}
	} else
		memset(&attr->mp_nexthop_local, 0, sizeof(attr->mp_nexthop_local));
	lua_pop(L, 1);

	lua_getfield(L, -1, "mp_len");
	if (!lua_isnil(L, -1)) {
		uint8_t script_len = (uint8_t)lua_tointeger(L, -1);
		uint8_t inferred = attr->mp_nexthop_len;

		/*
		 * Address decode may have raised len to GLOBAL_AND_LL.
		 * Do not let the encoded original mp_len clobber that.
		 */
		if ((inferred == BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL
		     || inferred == BGP_ATTR_NHLEN_VPNV6_GLOBAL_AND_LL)
		    && script_len < inferred)
			; /* keep inferred */
		else
			attr->mp_nexthop_len = script_len;
	}
	lua_pop(L, 1);

	lua_getfield(L, -1, "ifindex");
	if (!lua_isnil(L, -1)) {
		ifindex_t script_ifindex = (ifindex_t)lua_tointeger(L, -1);

		/*
		 * Only override the flat "ifindex" key's decode if the
		 * script actually changed the nested value; otherwise a
		 * script that only touches the flat key (compat) would
		 * have its change clobbered by this unmodified default.
		 */
		if (script_ifindex != orig_nh_ifindex)
			attr->nh_ifindex = script_ifindex;
	}
	lua_pop(L, 1);

	lua_getfield(L, -1, "lla_ifindex");
	if (!lua_isnil(L, -1))
		attr->nh_lla_ifindex = (ifindex_t)lua_tointeger(L, -1);
	lua_pop(L, 1);

	lua_getfield(L, -1, "prefer_global");
	if (!lua_isnil(L, -1)) {
		if (lua_toboolean(L, -1))
			SET_FLAG(attr->nh_flags, BGP_ATTR_NH_MP_PREFER_GLOBAL);
		else
			UNSET_FLAG(attr->nh_flags, BGP_ATTR_NH_MP_PREFER_GLOBAL);
		if (old_nh_flags != attr->nh_flags)
			SET_FLAG(attr->rmap_change_flags,
				 BATTR_RMAP_IPV6_PREFER_GLOBAL_CHANGED);
	}
	lua_pop(L, 1);

	lua_pop(L, 1); /* nexthop table */
}


static void lua_push_evpn_table(lua_State *L, const struct attr *attr)
{
	struct bgp_route_evpn *bre = bgp_attr_get_evpn_overlay(attr);
	char buf[INET6_ADDRSTRLEN];

	lua_newtable(L);

	if (bre && bre->type == OVERLAY_INDEX_GATEWAY_IP) {
		ipaddr2str(&bre->gw_ip, buf, sizeof(buf));
		lua_pushstring(L, buf);
	} else
		lua_pushnil(L);
	lua_setfield(L, -2, "gateway_ip");

	lua_newtable(L);
	lua_pushboolean(L, CHECK_FLAG(attr->evpn_flags, ATTR_EVPN_FLAG_STICKY));
	lua_setfield(L, -2, "sticky");
	lua_pushboolean(L,
			CHECK_FLAG(attr->evpn_flags, ATTR_EVPN_FLAG_DEFAULT_GW));
	lua_setfield(L, -2, "default_gw");
	lua_pushboolean(L, CHECK_FLAG(attr->evpn_flags, ATTR_EVPN_FLAG_ROUTER));
	lua_setfield(L, -2, "router");
	lua_setfield(L, -2, "flags");
}

static void lua_decode_evpn_table(lua_State *L, int idx, struct attr *attr)
{
	lua_getfield(L, idx, "evpn");
	if (lua_isnil(L, -1) || !lua_istable(L, -1)) {
		lua_pop(L, 1);
		return;
	}

	lua_getfield(L, -1, "gateway_ip");
	if (lua_isnil(L, -1)) {
		struct bgp_route_evpn *old = bgp_attr_get_evpn_overlay(attr);

		/* Nil means "no gateway IP", not "delete ESI/MAC overlay". */
		if (old && old->type == OVERLAY_INDEX_GATEWAY_IP)
			bgp_attr_set_evpn_overlay(attr, NULL);
	} else {
		const char *str = lua_tostring(L, -1);
		struct ipaddr gw = {};
		struct bgp_route_evpn *old = bgp_attr_get_evpn_overlay(attr);
		struct bgp_route_evpn *bre;

		if (str && str2ipaddr(str, &gw) == 0) {
			if (old && old->type == OVERLAY_INDEX_GATEWAY_IP
			    && ipaddr_is_same(&old->gw_ip, &gw))
				; /* unchanged */
			else {
				bre = XCALLOC(MTYPE_BGP_EVPN_OVERLAY,
					      sizeof(struct bgp_route_evpn));
				bre->type = OVERLAY_INDEX_GATEWAY_IP;
				bre->gw_ip = gw;
				bgp_attr_set_evpn_overlay(attr, bre);
			}
		}
		/* parse failure: keep original overlay */
	}
	lua_pop(L, 1);

	lua_getfield(L, -1, "flags");
	if (lua_istable(L, -1)) {
		attr->evpn_flags = 0;
		lua_getfield(L, -1, "sticky");
		if (!lua_isnil(L, -1) && lua_toboolean(L, -1))
			SET_FLAG(attr->evpn_flags, ATTR_EVPN_FLAG_STICKY);
		lua_pop(L, 1);
		lua_getfield(L, -1, "default_gw");
		if (!lua_isnil(L, -1) && lua_toboolean(L, -1))
			SET_FLAG(attr->evpn_flags, ATTR_EVPN_FLAG_DEFAULT_GW);
		lua_pop(L, 1);
		lua_getfield(L, -1, "router");
		if (!lua_isnil(L, -1) && lua_toboolean(L, -1))
			SET_FLAG(attr->evpn_flags, ATTR_EVPN_FLAG_ROUTER);
		lua_pop(L, 1);
	}
	lua_pop(L, 1);

	lua_pop(L, 1); /* evpn */
}

void lua_push_bgp_path_info(lua_State *L, const struct bgp_path_info *path)
{
	lua_newtable(L);
	lua_pushstring(L, zebra_route_string(path->type));
	lua_setfield(L, -2, "type");
	lua_pushinteger(L, path->type);
	lua_setfield(L, -2, "type_id");
	lua_pushinteger(L, path->sub_type);
	lua_setfield(L, -2, "sub_type");
	/*
	 * Effective SR-TE color: extra (set sr-te color) or Color
	 * Extended Community.
	 */
	lua_pushinteger(L, bgp_path_info_get_srte_color(path));
	lua_setfield(L, -2, "srte_color");
}

void lua_decode_bgp_path_info(lua_State *L, int idx, struct bgp_path_info *path)
{
	lua_getfield(L, idx, "srte_color");
	if (!lua_isnil(L, -1))
		bgp_path_info_extra_get(path)->srte_color =
			(uint32_t)lua_tointeger(L, -1);
	lua_pop(L, 1);

	/* pop the path table */
	lua_pop(L, 1);
}

void lua_pushpeer(lua_State *L, const struct peer *peer)
{
	lua_newtable(L);
	lua_pushinteger(L, peer->as);
	lua_setfield(L, -2, "remote_as");
	lua_pushinteger(L, peer->local_as);
	lua_setfield(L, -2, "local_as");
	lua_pushinaddr(L, &peer->remote_id);
	lua_setfield(L, -2, "remote_id");
	lua_pushinaddr(L, &peer->local_id);
	lua_setfield(L, -2, "local_id");
	lua_pushstring(L, lookup_msg(bgp_status_msg, peer->connection->status,
				     NULL));
	lua_setfield(L, -2, "state");
	lua_pushstring(L, peer->desc ? peer->desc : "");
	lua_setfield(L, -2, "description");
	lua_pushinteger(L, peer->uptime);
	lua_setfield(L, -2, "uptime");
	lua_pushinteger(L, peer->readtime);
	lua_setfield(L, -2, "last_readtime");
	lua_pushinteger(L, peer->resettime);
	lua_setfield(L, -2, "last_resettime");
	lua_pushsockunion(L, peer->connection->su_local);
	lua_setfield(L, -2, "local_address");
	lua_pushsockunion(L, peer->connection->su_remote);
	lua_setfield(L, -2, "remote_address");
	lua_pushinteger(L, peer->cap);
	lua_setfield(L, -2, "capabilities");
	lua_pushinteger(L, peer->flags);
	lua_setfield(L, -2, "flags");
	lua_pushstring(L, peer->password ? peer->password : "");
	lua_setfield(L, -2, "password");

	/* Nested tables here */
	lua_newtable(L);
	{
		lua_newtable(L);
		{
			lua_pushinteger(L, peer->holdtime);
			lua_setfield(L, -2, "hold");
			lua_pushinteger(L, peer->keepalive);
			lua_setfield(L, -2, "keepalive");
			lua_pushinteger(L, peer->connect);
			lua_setfield(L, -2, "connect");
			lua_pushinteger(L, peer->routeadv);
			lua_setfield(L, -2, "route_advertisement");
		}
		lua_setfield(L, -2, "configured");

		lua_newtable(L);
		{
			lua_pushinteger(L, peer->v_holdtime);
			lua_setfield(L, -2, "hold");
			lua_pushinteger(L, peer->v_keepalive);
			lua_setfield(L, -2, "keepalive");
			lua_pushinteger(L, peer->v_connect);
			lua_setfield(L, -2, "connect");
			lua_pushinteger(L, peer->v_routeadv);
			lua_setfield(L, -2, "route_advertisement");
		}
		lua_setfield(L, -2, "negotiated");
	}
	lua_setfield(L, -2, "timers");

	lua_newtable(L);
	{
		lua_pushinteger(L, atomic_load_explicit(&peer->open_in,
							memory_order_relaxed));
		lua_setfield(L, -2, "open_in");
		lua_pushinteger(L, atomic_load_explicit(&peer->open_out,
							memory_order_relaxed));
		lua_setfield(L, -2, "open_out");
		lua_pushinteger(L, atomic_load_explicit(&peer->update_in,
							memory_order_relaxed));
		lua_setfield(L, -2, "update_in");
		lua_pushinteger(L, atomic_load_explicit(&peer->update_out,
							memory_order_relaxed));
		lua_setfield(L, -2, "update_out");
		lua_pushinteger(L, atomic_load_explicit(&peer->update_time,
							memory_order_relaxed));
		lua_setfield(L, -2, "update_time");
		lua_pushinteger(L, atomic_load_explicit(&peer->keepalive_in,
							memory_order_relaxed));
		lua_setfield(L, -2, "keepalive_in");
		lua_pushinteger(L, atomic_load_explicit(&peer->keepalive_out,
							memory_order_relaxed));
		lua_setfield(L, -2, "keepalive_out");
		lua_pushinteger(L, atomic_load_explicit(&peer->notify_in,
							memory_order_relaxed));
		lua_setfield(L, -2, "notify_in");
		lua_pushinteger(L, atomic_load_explicit(&peer->notify_out,
							memory_order_relaxed));
		lua_setfield(L, -2, "notify_out");
		lua_pushinteger(L, atomic_load_explicit(&peer->refresh_in,
							memory_order_relaxed));
		lua_setfield(L, -2, "refresh_in");
		lua_pushinteger(L, atomic_load_explicit(&peer->refresh_out,
							memory_order_relaxed));
		lua_setfield(L, -2, "refresh_out");
		lua_pushinteger(L, atomic_load_explicit(&peer->dynamic_cap_in,
							memory_order_relaxed));
		lua_setfield(L, -2, "dynamic_cap_in");
		lua_pushinteger(L, atomic_load_explicit(&peer->dynamic_cap_out,
							memory_order_relaxed));
		lua_setfield(L, -2, "dynamic_cap_out");
		lua_pushinteger(L, peer->established);
		lua_setfield(L, -2, "times_established");
		lua_pushinteger(L, peer->dropped);
		lua_setfield(L, -2, "times_dropped");
	}
	lua_setfield(L, -2, "stats");
}

void lua_pushattr(lua_State *L, const struct attr *attr)
{
	lua_newtable(L);

	lua_push_optional_uint(L, attr, ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC),
			       attr->med, "metric");

	lua_pushinteger(L, attr->nh_ifindex);
	lua_setfield(L, -2, "ifindex");

	if (attr->aspath && attr->aspath->str)
		lua_pushstring(L, attr->aspath->str);
	else
		lua_pushnil(L);
	lua_setfield(L, -2, "aspath");

	lua_push_optional_uint(L, attr, ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF),
			       attr->local_pref, "localpref");

	switch (attr->origin) {
	case BGP_ORIGIN_IGP:
		lua_pushstring(L, "igp");
		break;
	case BGP_ORIGIN_EGP:
		lua_pushstring(L, "egp");
		break;
	case BGP_ORIGIN_INCOMPLETE:
	default:
		lua_pushstring(L, "incomplete");
		break;
	}
	lua_setfield(L, -2, "origin");

	lua_pushinteger(L, attr->weight);
	lua_setfield(L, -2, "weight");

	lua_pushinteger(L, attr->distance);
	lua_setfield(L, -2, "distance");

	lua_pushinteger(L, attr->tag);
	lua_setfield(L, -2, "tag");

	lua_pushinteger(L, attr->rmap_table_id);
	lua_setfield(L, -2, "table");

	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_PREFIX_SID)))
		lua_pushinteger(L, attr->label_index);
	else
		lua_pushnil(L);
	lua_setfield(L, -2, "label_index");

	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_AIGP)))
		lua_pushinteger(L, (lua_Integer)bgp_attr_get_aigp_metric(attr));
	else
		lua_pushnil(L);
	lua_setfield(L, -2, "aigp_metric");

	lua_pushboolean(L, CHECK_FLAG(attr->flag,
				      ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE)));
	lua_setfield(L, -2, "atomic_aggregate");

	lua_push_community_field(L, bgp_attr_get_community(attr), "community");
	lua_push_lcommunity_field(L, bgp_attr_get_lcommunity(attr),
				  "large_community");
	lua_push_ecommunity_field(L, bgp_attr_get_ecommunity(attr),
				  "extcommunity");
	lua_push_ecommunity_field(L, bgp_attr_get_ipv6_ecommunity(attr),
				  "ipv6_extcommunity");

	lua_push_nexthop_table(L, attr);
	lua_setfield(L, -2, "nexthop");

	lua_pushinteger(L, attr->rmap_change_flags);
	lua_setfield(L, -2, "rmap_change_flags");

	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_AGGREGATOR))) {
		char buf[INET_ADDRSTRLEN];

		lua_newtable(L);
		lua_pushinteger(L, attr->aggregator_as);
		lua_setfield(L, -2, "as");
		inet_ntop(AF_INET, &attr->aggregator_addr, buf, sizeof(buf));
		lua_pushstring(L, buf);
		lua_setfield(L, -2, "address");
	} else
		lua_pushnil(L);
	lua_setfield(L, -2, "aggregator");

	if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID))) {
		char buf[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, &attr->originator_id, buf, sizeof(buf));
		lua_pushstring(L, buf);
	} else
		lua_pushnil(L);
	lua_setfield(L, -2, "originator_id");

	lua_push_evpn_table(L, attr);
	lua_setfield(L, -2, "evpn");
}

void lua_decode_attr(lua_State *L, int idx, struct attr *attr)
{
	uint64_t val;
	ifindex_t orig_nh_ifindex = attr->nh_ifindex;

	if (lua_decode_optional_uint(L, idx, "metric", attr,
				     ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC), &val))
		bgp_attr_set_med(attr, (uint32_t)val);

	lua_getfield(L, idx, "ifindex");
	if (!lua_isnil(L, -1))
		attr->nh_ifindex = (ifindex_t)lua_tointeger(L, -1);
	lua_pop(L, 1);

	lua_decode_aspath_field(L, idx, attr);

	if (lua_decode_optional_uint(L, idx, "localpref", attr, ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF),
				     &val))
		attr->local_pref = (uint32_t)val;

	lua_getfield(L, idx, "origin");
	if (!lua_isnil(L, -1)) {
		if (lua_isinteger(L, -1))
			attr->origin = (uint8_t)lua_tointeger(L, -1);
		else {
			const char *origin = lua_tostring(L, -1);

			if (origin && strmatch(origin, "igp"))
				attr->origin = BGP_ORIGIN_IGP;
			else if (origin && strmatch(origin, "egp"))
				attr->origin = BGP_ORIGIN_EGP;
			else if (origin && strmatch(origin, "incomplete"))
				attr->origin = BGP_ORIGIN_INCOMPLETE;
		}
	}
	lua_pop(L, 1);

	lua_getfield(L, idx, "weight");
	if (!lua_isnil(L, -1))
		attr->weight = (uint32_t)lua_tointeger(L, -1);
	lua_pop(L, 1);

	lua_getfield(L, idx, "distance");
	if (!lua_isnil(L, -1))
		attr->distance = (uint8_t)lua_tointeger(L, -1);
	lua_pop(L, 1);

	lua_getfield(L, idx, "tag");
	if (!lua_isnil(L, -1))
		attr->tag = (route_tag_t)lua_tointeger(L, -1);
	lua_pop(L, 1);

	lua_getfield(L, idx, "table");
	if (!lua_isnil(L, -1))
		attr->rmap_table_id = (uint32_t)lua_tointeger(L, -1);
	lua_pop(L, 1);

	lua_getfield(L, idx, "label_index");
	{
		uint32_t label_index =
			lua_isnil(L, -1) ? 0 : (uint32_t)lua_tointeger(L, -1);

		/* nil or 0 clears Prefix-SID presence, consistent with
		 * other optional numeric attributes.
		 */
		if (label_index) {
			attr->label_index = label_index;
			SET_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_PREFIX_SID));
		} else {
			attr->label_index = 0;
			bgp_attr_unset(attr, BGP_ATTR_PREFIX_SID);
		}
	}
	lua_pop(L, 1);

	lua_getfield(L, idx, "aigp_metric");
	if (lua_isnil(L, -1))
		bgp_attr_unset_aigp_metric(attr);
	else
		bgp_attr_set_aigp_metric(attr, (uint64_t)lua_tointeger(L, -1));
	lua_pop(L, 1);

	lua_getfield(L, idx, "atomic_aggregate");
	if (!lua_isnil(L, -1) && lua_toboolean(L, -1))
		SET_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE));
	else
		bgp_attr_unset(attr, BGP_ATTR_ATOMIC_AGGREGATE);
	lua_pop(L, 1);

	lua_decode_community_field(L, idx, attr);
	lua_decode_lcommunity_field(L, idx, attr);
	lua_decode_ecommunity_field(L, idx, attr);
	lua_decode_ipv6_ecommunity_field(L, idx, attr);

	/*
	 * Script rmap_change_flags are the base bitfield (peer-address,
	 * unchanged, etc.). Nexthop decode ORs BATTR_RMAP_*_CHANGED on top
	 * so returning the encoded table does not wipe auto-detected bits.
	 */
	lua_getfield(L, idx, "rmap_change_flags");
	if (!lua_isnil(L, -1))
		attr->rmap_change_flags = (uint16_t)lua_tointeger(L, -1);
	lua_pop(L, 1);

	lua_decode_nexthop_table(L, idx, attr, orig_nh_ifindex);

	lua_getfield(L, idx, "aggregator");
	if (lua_isnil(L, -1)) {
		bgp_attr_unset(attr, BGP_ATTR_AGGREGATOR);
		attr->aggregator_as = 0;
		memset(&attr->aggregator_addr, 0, sizeof(attr->aggregator_addr));
	} else if (lua_istable(L, -1)) {
		lua_getfield(L, -1, "as");
		if (!lua_isnil(L, -1))
			attr->aggregator_as = (as_t)lua_tointeger(L, -1);
		lua_pop(L, 1);
		lua_getfield(L, -1, "address");
		if (!lua_isnil(L, -1)) {
			const char *str = lua_tostring(L, -1);

			if (str)
				inet_pton(AF_INET, str, &attr->aggregator_addr);
		}
		lua_pop(L, 1);
		SET_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_AGGREGATOR));
	}
	lua_pop(L, 1);

	lua_getfield(L, idx, "originator_id");
	if (lua_isnil(L, -1)) {
		bgp_attr_unset(attr, BGP_ATTR_ORIGINATOR_ID);
		memset(&attr->originator_id, 0, sizeof(attr->originator_id));
	} else {
		const char *str = lua_tostring(L, -1);

		if (str && inet_pton(AF_INET, str, &attr->originator_id) == 1)
			SET_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID));
	}
	lua_pop(L, 1);

	lua_decode_evpn_table(L, idx, attr);

	/* pop the attributes table */
	lua_pop(L, 1);
}

void *lua_toattr(lua_State *L, int idx)
{
	struct attr *attr = XCALLOC(MTYPE_TMP, sizeof(struct attr));

	lua_decode_attr(L, idx, attr);
	return attr;
}

struct frrscript_codec frrscript_codecs_bgpd[] = {
	{.typename = "peer",
	 .encoder = (encoder_func)lua_pushpeer,
	 .decoder = NULL},
	{.typename = "attr",
	 .encoder = (encoder_func)lua_pushattr,
	 .decoder = lua_toattr},
	{}};

void bgp_script_init(void)
{
	frrscript_register_type_codecs(frrscript_codecs_bgpd);
}

#endif /* HAVE_SCRIPTING */
