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
#include "frratomic.h"
#include "frrscript.h"

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
static bool lua_decode_optional_uint(lua_State *L, int idx, const char *key,
				     struct attr *attr, uint64_t flagbit,
				     uint64_t *out)
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
		UNSET_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_AS_PATH));
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
		UNSET_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_AS_PATH));
	lua_pop(L, 1);
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
		UNSET_FLAG(dst->flag, ATTR_FLAG_BIT(BGP_ATTR_AS_PATH));
}

void bgp_attr_script_apply(struct attr *dst, struct attr *src)
{
	/* metric / MED */
	if (CHECK_FLAG(src->flag, ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC)))
		bgp_attr_set_med(dst, src->med);
	else {
		UNSET_FLAG(dst->flag, ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC));
		dst->med = 0;
	}

	/* local preference */
	if (CHECK_FLAG(src->flag, ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF))) {
		SET_FLAG(dst->flag, ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF));
		dst->local_pref = src->local_pref;
	} else {
		UNSET_FLAG(dst->flag, ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF));
		dst->local_pref = 0;
	}

	/* nexthop ifindex (flat key; nested nexthop table added later) */
	dst->nh_ifindex = src->nh_ifindex;

	dst->origin = src->origin;
	dst->weight = src->weight;
	dst->distance = src->distance;
	dst->tag = src->tag;

	bgp_attr_script_apply_aspath(dst, src);
}

void bgp_attr_script_discard(struct attr *working, const struct attr *orig)
{
	if (working->aspath && working->aspath != orig->aspath
	    && working->aspath->refcnt == 0)
		aspath_free(working->aspath);
	working->aspath = NULL;
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
}

void lua_decode_attr(lua_State *L, int idx, struct attr *attr)
{
	uint64_t val;

	if (lua_decode_optional_uint(L, idx, "metric", attr,
				     ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC),
				     &val))
		bgp_attr_set_med(attr, (uint32_t)val);

	lua_getfield(L, idx, "ifindex");
	if (!lua_isnil(L, -1))
		attr->nh_ifindex = (ifindex_t)lua_tointeger(L, -1);
	lua_pop(L, 1);

	lua_decode_aspath_field(L, idx, attr);

	if (lua_decode_optional_uint(L, idx, "localpref", attr,
				     ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF),
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
