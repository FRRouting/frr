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
#include "frratomic.h"
#include "frrscript.h"

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
	lua_pushsockunion(L, peer->su_local);
	lua_setfield(L, -2, "local_address");
	lua_pushsockunion(L, peer->su_remote);
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
	lua_pushinteger(L, attr->med);
	lua_setfield(L, -2, "metric");
	lua_pushinteger(L, attr->nh_ifindex);
	lua_setfield(L, -2, "ifindex");
	lua_pushstring(L, attr->aspath->str);
	lua_setfield(L, -2, "aspath");
	lua_pushinteger(L, attr->local_pref);
	lua_setfield(L, -2, "localpref");
}

void lua_decode_attr(lua_State *L, int idx, struct attr *attr)
{
	lua_getfield(L, idx, "metric");
	attr->med = lua_tointeger(L, -1);
	lua_pop(L, 1);
	lua_getfield(L, idx, "ifindex");
	attr->nh_ifindex = lua_tointeger(L, -1);
	lua_pop(L, 1);
	lua_getfield(L, idx, "aspath");
	attr->aspath = aspath_str2aspath(lua_tostring(L, -1),
					 bgp_get_asnotation(NULL));
	lua_pop(L, 1);
	lua_getfield(L, idx, "localpref");
	attr->local_pref = lua_tointeger(L, -1);
	lua_pop(L, 1);
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
