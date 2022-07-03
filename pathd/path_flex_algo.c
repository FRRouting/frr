/* Flex-algo candidate paths
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

#include "zclient.h"
#include "lib_errors.h"
#include "vector.h"
#include "memory.h"
#include "zapi_fae.h"
#include "vty.h"
#include "pathd/pathd.h"
#include "pathd/path_flex_algo.h"
#include "pathd/path_zebra.h"
#include "pathd/path_debug.h"

unsigned long path_debug_fa;

/*
 * throttle interval for changes due to route updates
 */
#define _FA_APPLY_DELAY 2

DEFINE_MTYPE_STATIC(PATHD, FLEX_ALGO_IGP_INSTANCE, "Flex algo IGP instance");
DEFINE_MTYPE_STATIC(PATHD, FLEX_ALGO_ENDPOINT, "Flex algo endpoint");
DEFINE_MTYPE_STATIC(PATHD, SEG_LIST_NAME, "Flex algo segment list name");
DEFINE_MTYPE_STATIC(PATHD, CANDIDATE_ENTRY, "Flex algo candidate entry");
DEFINE_MTYPE_STATIC(PATHD, ISIS_AREA_TAG, "isis area tag");
DEFINE_MTYPE_STATIC(PATHD, SESSION_ID_STR, "session ID string");

#define DEBUG_IGP_DEFAULTS 1

/* forward */
static bool _igp_defaults_valid(void);

/*
 * srte_apply_changes() is potentialy expensive as it scans the entire
 * policy database. The idea here is to limit the frequency of calls
 * to srte_apply_changes() when many FAE UPDATEs are arriving from the IGP.
 *
 * From quiescent state, the first call to fa_apply_changes() should
 * call srte_apply_changes() and then start a timer.
 *
 * Any subsequent calls to fa_apply_changes() during the timer period
 * set the "changes needed" bit and return immediately.
 *
 * When the timer expires, if there are pending changes, call
 * srte_apply_changes() and restart the timer, otherwise reset to
 * the quiescent state.
 */
static bool need_to_apply_changes;
static struct event *pThreadApplyChanges;

static void _fa_cb_apply_changes(struct event *event)
{
	if (need_to_apply_changes) {
		srte_apply_changes();
		need_to_apply_changes = false;
		event_add_timer(master, _fa_cb_apply_changes, NULL,
				 _FA_APPLY_DELAY, &pThreadApplyChanges);
	} else {
		pThreadApplyChanges = NULL;
	}
	return;
}

static void fa_apply_changes(void)
{
	if (pThreadApplyChanges) {
		need_to_apply_changes = true;
		return;
	}

	srte_apply_changes();
	need_to_apply_changes = false;

	event_add_timer(master, _fa_cb_apply_changes, NULL, _FA_APPLY_DELAY,
			 &pThreadApplyChanges);
}

static void fa_candidate_endpoint_del_all_default_igps(void)
{
	/*
	 * loop over all policies and their candidates to find
	 * flex-algo candidates with F_CANDIDATE_FLEX_ALGO_IGP_USE_DEFAULTS
	 */
	struct srte_policy *policy;

	RB_FOREACH (policy, srte_policy_head, &srte_policies) {
		struct srte_candidate *candidate;

		RB_FOREACH (candidate, srte_candidate_head,
			    &policy->candidate_paths) {

			if (SRTE_CANDIDATE_TYPE_FLEX_ALGO != candidate->type)
				continue;

			if (!CHECK_FLAG(candidate->flags,
					F_CANDIDATE_HAS_FLEX_ALGO_NUMBER))
				continue;

			if (!CHECK_FLAG(candidate->flags,
					F_CANDIDATE_FLEX_ALGO_IGP_USE_DEFAULTS))
				continue;

			if (!CHECK_FLAG(candidate->flags,
					F_CANDIDATE_FLEX_ALGO_REGISTERED))
				continue;

			fa_candidate_endpoint_del(candidate);
		}
	}
}

static void fa_candidate_endpoint_add_all_default_igps(void)
{
	if (!_igp_defaults_valid())
		return;

	/*
	 * loop over all policies and their candidates to find
	 * flex-algo candidates with F_CANDIDATE_FLEX_ALGO_IGP_USE_DEFAULTS
	 */
	struct srte_policy *policy;

	RB_FOREACH (policy, srte_policy_head, &srte_policies) {
		struct srte_candidate *candidate;

		RB_FOREACH (candidate, srte_candidate_head,
			    &policy->candidate_paths) {

			if (SRTE_CANDIDATE_TYPE_FLEX_ALGO != candidate->type)
				continue;

			if (!CHECK_FLAG(candidate->flags,
					F_CANDIDATE_HAS_FLEX_ALGO_NUMBER))
				continue;

			if (!CHECK_FLAG(candidate->flags,
					F_CANDIDATE_FLEX_ALGO_IGP_USE_DEFAULTS))
				continue;

			fa_candidate_endpoint_add(candidate);
		}
	}
}

struct flex_algo_igp_defaults {
	uint8_t igp_proto;
	uint16_t igp_instance;
	vrf_id_t igp_vrf_id;
	char *isis_area;
};

struct flex_algo_igp_defaults _igp_defaults;

static bool _igp_defaults_are_valid;

static void _igp_defaults_changed(void)
{
	bool newstate = _igp_defaults_valid();
	bool oldstate = _igp_defaults_are_valid;

	_igp_defaults_are_valid = newstate;

	if (oldstate) {
		/*
		 * IGP parameters were valid before, so we must
		 * deregister any existing endpoint registrations
		 * before possibly re-registering (with the new IGP params)
		 */
		fa_candidate_endpoint_del_all_default_igps();
	}

	if (newstate)
		fa_candidate_endpoint_add_all_default_igps();
}

static bool _igp_defaults_valid(void)
{
	/* currently we only support isis */
	if (ZEBRA_ROUTE_ISIS != _igp_defaults.igp_proto) {
#if DEBUG_IGP_DEFAULTS
		FA_IGPDEF_DEBUG("%s: NO: igp_proto %u, wanted %u", __func__,
				_igp_defaults.igp_proto, ZEBRA_ROUTE_ISIS);
#endif
		return false;
	} else {
		if (!_igp_defaults.isis_area) {
#if DEBUG_IGP_DEFAULTS
			FA_IGPDEF_DEBUG("%s: NO: isis_area is unset", __func__);
#endif
			return false;
		}
	}

#if DEBUG_IGP_DEFAULTS
	FA_IGPDEF_DEBUG("%s: YES", __func__);
#endif
	/* any vrf id and any instance are valid */
	return true;
}

int fa_check_default_igp_proto(uint8_t proto)
{
	if (ZEBRA_ROUTE_ISIS == proto) {
#if DEBUG_IGP_DEFAULTS
		FA_IGPDEF_DEBUG("%s: proto is \"%s\": valid", __func__,
				zebra_route_string(proto));
#endif
		return 0;
	}
#if DEBUG_IGP_DEFAULTS
	FA_IGPDEF_DEBUG("%s: proto is \"%s\": not valid", __func__,
			zebra_route_string(proto));
#endif
	return -1;
}

int fa_set_default_igp_proto(uint8_t proto)
{
	bool different = (proto != _igp_defaults.igp_proto);

#if DEBUG_IGP_DEFAULTS
	FA_IGPDEF_DEBUG("%s: proto is \"%s\" (%s)", __func__,
			zebra_route_string(proto),
			(different ? "changed" : "same"));
#endif
	switch (proto) {
	case ZEBRA_ROUTE_ISIS:
		_igp_defaults.igp_proto = proto;
		break;
	default:
#if DEBUG_IGP_DEFAULTS
		FA_IGPDEF_DEBUG("%s: invalid proto, not setting", __func__);
#endif
		return -1;
	}
#if DEBUG_IGP_DEFAULTS
	FA_IGPDEF_DEBUG("%s: valid proto, set", __func__);
#endif
	if (different)
		_igp_defaults_changed();
	return 0;
}

int fa_set_default_igp_instance(uint16_t instance)
{
	bool different = (instance != _igp_defaults.igp_instance);

	_igp_defaults.igp_instance = instance;
#if DEBUG_IGP_DEFAULTS
	FA_IGPDEF_DEBUG("%s: instance set to %u", __func__, instance);
#endif
	if (different)
		_igp_defaults_changed();
	return 0;
}

int fa_set_default_igp_vrf_id(vrf_id_t vrf_id)
{
	bool different = (vrf_id != _igp_defaults.igp_vrf_id);

	_igp_defaults.igp_vrf_id = vrf_id;
#if DEBUG_IGP_DEFAULTS
	FA_IGPDEF_DEBUG("%s: vrf ID set to %u", __func__, vrf_id);
#endif
	if (different)
		_igp_defaults_changed();
	return 0;
}

int fa_set_default_igp_isis_area_tag(const char *area_tag)
{
	bool different = false;

	if (!_igp_defaults.isis_area && area_tag)
		different = true;
	if ((_igp_defaults.isis_area && area_tag)
	    && strcmp(_igp_defaults.isis_area, area_tag))
		different = true;

	if (different) {
		XFREE(MTYPE_ISIS_AREA_TAG, _igp_defaults.isis_area);
		_igp_defaults.isis_area =
			XSTRDUP(MTYPE_ISIS_AREA_TAG, area_tag);
	}
#if DEBUG_IGP_DEFAULTS
	FA_IGPDEF_DEBUG("%s: isis area tag set to: \"%s\"", __func__,
			_igp_defaults.isis_area);
#endif
	if (different)
		_igp_defaults_changed();
	return 0;
}

void fa_vty_igp_defaults_show(struct vty *vty)
{
	unsigned int indent = 4;

	vty_out(vty, "%*sIGP proto: %s\n", indent, "",
		zebra_route_string(_igp_defaults.igp_proto));
	vty_out(vty, "%*sIGP instance: %u\n", indent, "",
		_igp_defaults.igp_instance);
	vty_out(vty, "%*sIGP vrf ID: %u\n", indent, "",
		_igp_defaults.igp_vrf_id);
	vty_out(vty, "%*sIGP isis area tag: \"%s\"\n", indent, "",
		_igp_defaults.isis_area);
	vty_out(vty, "%*sValid: %s\n", indent, "",
		(_igp_defaults_valid() ? "yes" : "no"));
}

struct flex_algo_igp_instance {
	uint8_t proto;
	uint8_t flags;
#define FAII_FLAG_SESSION_ID 0x01 /* session_id valid */
	uint16_t instance;
	uint32_t session_id;
	uint32_t vrf_id;
	uint32_t isis_z_area_id; /* only valid if FAII_FLAG_SESSION_ID set */
	char *isis_area;
};

static void _register(struct srte_candidate *c,
		      struct flex_algo_igp_instance *p)
{
	FA_DEBUG("%s: calling path_zebra_fae_register(true)", __func__);
	/* clang-format off */
	path_zebra_fae_register(
		true,
		&c->policy->endpoint,
		c->flex_algo_number,
		p->proto,
		p->instance,
		p->session_id,
		p->vrf_id,
		p->isis_z_area_id);
	/* clang-format on */
}

static void _unregister(struct srte_candidate *c,
			struct flex_algo_igp_instance *p)
{
	FA_DEBUG("%s: calling path_zebra_fae_register(false)", __func__);
	/* clang-format off */
	path_zebra_fae_register(
		false,
		&c->policy->endpoint,
		c->flex_algo_number,
		p->proto,
		p->instance,
		p->session_id,
		p->vrf_id,
		p->isis_z_area_id);
	/* clang-format on */
}

/*
 * Candidate list used by each endpoint structure
 */
PREDECL_SORTLIST_UNIQ(cand);
struct candidate_entry {
	struct cand_item ci;
	struct srte_candidate *candidate;
};

static int _cand_cmp(const struct candidate_entry *c1,
		     const struct candidate_entry *c2)
{
	return c1->candidate - c2->candidate;
}

DECLARE_SORTLIST_UNIQ(cand, struct candidate_entry, ci, _cand_cmp);

/*
 * Endpoint hash to track candidate paths of type "flex-algo"
 */
PREDECL_HASH(fae);
struct flex_algo_endpoint {
	struct fae_item faei;

	struct ipaddr endpoint;
	vrf_id_t vrf_id;
	uint16_t igp_instance;
	uint8_t igp_proto;
	uint8_t algorithm;
	char *isis_area;

	struct cand_head candidates;

	/*
	 * This field is set up for a single nexthop, but in the
	 * future we can change it to hold a set of ECMP nexthops
	 */
	struct zapi_srte_tunnel sid_list;
};

static int _flex_algo_endpoint_cmp(const struct flex_algo_endpoint *f1,
				   const struct flex_algo_endpoint *f2)
{
	if (f1->algorithm != f2->algorithm)
		return true;
	if (ipaddr_cmp(&f1->endpoint, &f2->endpoint))
		return true;
	if (f1->vrf_id != f2->vrf_id)
		return true;
	if (f1->igp_instance != f2->igp_instance)
		return true;
	if (f1->igp_proto != f2->igp_proto)
		return true;
	if (f1->isis_area && !f2->isis_area)
		return true;
	if ((f1->isis_area && f2->isis_area)
	    && strcmp(f1->isis_area, f2->isis_area))
		return true;

	return false;
}

static uint32_t _flex_algo_endpoint_hash(const struct flex_algo_endpoint *f)
{
	uint32_t accumulator;

	accumulator = f->algorithm;
	accumulator += f->igp_instance;
	accumulator += (f->vrf_id << 8);
	accumulator += (f->igp_proto << 16);

	switch (ipaddr_family(&f->endpoint)) {
	case AF_INET:
		accumulator += f->endpoint.ipaddr_v4.s_addr;
		break;
	case AF_INET6:
		accumulator += f->endpoint.ipaddr_v6.__in6_u.__u6_addr32[0];
	default:
		break;
	}

	if ((ZEBRA_ROUTE_ISIS == f->igp_proto) && f->isis_area) {
		char *p = (char *)&accumulator;

		for (unsigned int i = 0; i < strlen(f->isis_area); ++i) {
			*(p + (i % sizeof(accumulator))) = f->isis_area[i];
		}
	}

	return accumulator;
}

DECLARE_HASH(fae, struct flex_algo_endpoint, faei, _flex_algo_endpoint_cmp,
	     _flex_algo_endpoint_hash);

static struct fae_head _faehash;

/*
 * IGP instances
 */

static vector _igp_instance;

/*
 * We don't expect to have many IGP instances providing flex-algo endpoint
 * services. For this implementation, we can just use a small array and
 * do a linear search as needed.
 *
 * As of this initial implementation, there is not a way for the user to
 * specify in configuration which protocol or instance a policy should
 * use to look up endpoints. So we allow defaulting the protocol (should
 * probably match the import-te protocol). Callers should specify
 * instance 0 until there is a mechanism to specify otherwise.
 *
 * proto == ZEBRA_ROUTE_ALL means to use the default protocol
 */

static void fa_igp_check_vector_size(unsigned int size)
{
	if (!_igp_instance) {
		if (size < 20)
			size = 20;
		_igp_instance = vector_init(size);
	} else
		vector_ensure(_igp_instance, size);
}

/*
 * if area_tag is non-NULL, use it in comparison, otherwise use z_area_id.
 */
static struct flex_algo_igp_instance *
fa_igp_find_p(uint8_t proto, uint16_t instance, vrf_id_t vrf_id, char *area_tag,
	      uint32_t z_area_id)
{
	struct flex_algo_igp_instance *p;

	fa_igp_check_vector_size(0);

	FA_DEBUG("%s: want proto %hhu, instance %u, vrf_id %u, area_tag %s",
		 __func__, proto, instance, vrf_id,
		 (area_tag ? area_tag : "(nil)"));

	for (unsigned int i = 0; i < vector_active(_igp_instance); ++i) {
		p = vector_slot(_igp_instance, i);
		if (!p)
			continue;
		if (p->proto != proto)
			continue;
		if (p->instance != instance)
			continue;
		if (p->vrf_id != vrf_id)
			continue;
		if (p->proto == ZEBRA_ROUTE_ISIS) {
			if (area_tag) {
				if (!p->isis_area)
					continue;
				if (strcmp(p->isis_area, area_tag))
					continue;
			} else {
				if (z_area_id != p->isis_z_area_id)
					continue;
			}
		}
		return p;
	}
	return NULL;
}

static struct flex_algo_igp_instance *fa_igp_find_ready_p(uint8_t proto,
							  uint16_t instance,
							  vrf_id_t vrf_id,
							  char *area_tag)
{
	struct flex_algo_igp_instance *p;

	assert(area_tag);

	p = fa_igp_find_p(proto, instance, vrf_id, area_tag, 0);

	if (p && CHECK_FLAG(p->flags, FAII_FLAG_SESSION_ID))
		return p;

	return NULL;
}

/*
 * session_id_valid indicates that we have received a "ready" message
 * for this IGP entry.
 */
static void fa_igp_add(uint8_t proto, uint16_t instance, vrf_id_t vrf_id,
		       char *area_tag, bool session_id_valid,
		       uint16_t session_id, bool z_area_id_valid,
		       uint32_t z_area_id)
{
	struct flex_algo_igp_instance *p;

	assert(area_tag);
	p = fa_igp_find_p(proto, instance, vrf_id, area_tag, 0);
	if (p) {
		/*
		 * Already have it. Make sure there isn't an implicit
		 * "ready" state change attempt.
		 *
		 * We should only get here via a call to
		 * fa_candidate_endpoint_add() which sets up a
		 * not-ready IGP entry.
		 */
		assert(session_id_valid
		       == !!CHECK_FLAG(p->flags, FAII_FLAG_SESSION_ID));
		return;
	}

	p = XCALLOC(MTYPE_FLEX_ALGO_IGP_INSTANCE,
		    sizeof(struct flex_algo_igp_instance));
	p->proto = proto;
	p->instance = instance;
	if (session_id_valid) {
		p->session_id = session_id;
		SET_FLAG(p->flags, FAII_FLAG_SESSION_ID);
	}
	if (z_area_id_valid)
		p->isis_z_area_id = z_area_id;
	p->vrf_id = vrf_id;

	if (ZEBRA_ROUTE_ISIS == proto) {
		p->isis_area = XSTRDUP(MTYPE_ISIS_AREA_TAG, area_tag);
	}
	FA_DEBUG("%s: adding IGP: p=%hhu, i=%u, v=%u, a=%s, sv=%u, s=%u",
		 __func__, proto, instance, vrf_id, (area_tag ? area_tag : ""),
		 (session_id_valid ? 1 : 0), session_id);

	(void)vector_set(_igp_instance, p);
}


/*
 * display the IGP instance table
 */
void fa_vty_igp_show_all(struct vty *vty)
{
	bool printed_header = false;
	fa_igp_check_vector_size(0);

	for (unsigned int i = 0; i < vector_active(_igp_instance); ++i) {
		struct flex_algo_igp_instance *p;
		struct vrf *v;
		char *sSI;
		char *sZID;
		char *sAT;
		bool ready;

		p = vector_slot(_igp_instance, i);
		if (!p)
			continue;
		v = vrf_lookup_by_id(p->vrf_id);

		/* clang-format off */
		sAT = NULL;
		if (p->proto == ZEBRA_ROUTE_ISIS)
			sAT = p->isis_area;

		if (!printed_header) {
			printed_header = true;
			vty_out(vty, "* = Ready\n");
			vty_out(vty, " %-10s %6s %7s %-20s %8s %-32s\n",
				"proto", "inst", "session", "vrf",
				"isis-zid", "isis-area-tag");
		}
		sSI = NULL;
		sZID = NULL;
		ready = false;
		if (CHECK_FLAG(p->flags, FAII_FLAG_SESSION_ID)) {
			ready = true;
			sSI = asprintfrr(MTYPE_SESSION_ID_STR,
				"%7u", p->session_id);
			sZID = asprintfrr(MTYPE_SESSION_ID_STR,
				"%08x", p->isis_z_area_id);
		}
		vty_out(vty, "%c%-10s %6u %7s %-20s %8s %-32s\n",
			(ready ? '*' : ' '),
			zebra_route_string(p->proto),
			p->instance,
			(sSI ? sSI : "-"),
			(v ? v->name : "?"),
			(sZID ? sZID : ""),
			(sAT ? sAT : ""));
		XFREE(MTYPE_SESSION_ID_STR, sSI);
		XFREE(MTYPE_SESSION_ID_STR, sZID);
		/* clang-format on */
	}
}

static const char *_label_cstr(uint32_t label)
{
	switch (label) {
	case MPLS_LABEL_NONE:
		return "-";
	case MPLS_LABEL_IMPLICIT_NULL:
		return "imp-null";
	case MPLS_LABEL_IPV4_EXPLICIT_NULL:
	case MPLS_LABEL_IPV6_EXPLICIT_NULL:
		return "exp-null";
	default:
		return NULL;
	}
}

/*
 * display the endpoint table
 */
void fa_vty_endpoint_show_all(struct vty *vty, bool detail)
{
	bool printed_header = false;
	struct flex_algo_endpoint *f;

	frr_each (fae, &_faehash, f) {
		struct vrf *v;
		char *sAT;

		if (!printed_header) {
			vty_out(vty, "%-15s %3s %-5s %-10s %7s %-32s\n",
				"endpoint", "alg", "proto", "vrf", "inst",
				"area");
		}

		/* clang-format off */
		sAT = NULL;
		if (f->igp_proto == ZEBRA_ROUTE_ISIS)
			sAT = f->isis_area;

		v = vrf_lookup_by_id(f->vrf_id);
		vty_out(vty, "%-15pIA %3u %-5s %-10s %7u %-32s\n",
			&f->endpoint,
			f->algorithm,
			zebra_route_string(f->igp_proto),
			v->name,
			f->igp_instance,
			(sAT? sAT: ""));

		if (detail) {
			vty_out(vty, "  SID-list:");
			if (!f->sid_list.label_num) {
				vty_out(vty, "(undefined)\n");
			} else {
				for (int i = 0; i < f->sid_list.label_num; ++i) {
					const char *ls;

					ls = _label_cstr(f->sid_list.labels[i]);
					if (ls)
						vty_out(vty, " %s", ls);
					else
						vty_out(vty, " %u",
							f->sid_list.labels[i]);
				}
				vty_out(vty, "\n");
			}

			struct candidate_entry *ce;

			frr_each(cand, &f->candidates, ce) {
				struct srte_candidate *c;

				c = ce->candidate;
				assert(SRTE_CANDIDATE_TYPE_FLEX_ALGO
					== c->type);

				vty_out(vty,
					"  Candidate name \"%s\", policy \"%s\"\n",
					c->name,
					(c->policy ? c->policy->name : "?"));
			}

		}
		/* clang-format on */
	}
}

/*
 * This function is called when we receive a FAE_READY message.
 * We note the zapi rendezvous parameters so we can later send
 * endpoint registration requests.
 */
void fa_igp_handle_ready(struct zapi_fae_daemon_id *di,
			 struct zapi_fae_igp_discriminator *d)
{
	struct flex_algo_igp_instance *p;

	/*
	 * Did we record this igp-ready previously?
	 */
	assert(d->proto_data.isis.area_tag);
	p = fa_igp_find_p(di->proto, di->instance, d->vrf_id,
			  d->proto_data.isis.area_tag, 0);

	FA_DEBUG("%s: proto %u, instance %u, vrf_id %d: p=%p", __func__,
		 di->proto, di->instance, d->vrf_id, p);

	if (p) {
		bool need_clear = false;

		/*
		 * Set new session id in all cases
		 */
		p->session_id = di->session_id;

		/*
		 * Set isis_z_area_id if proto is isis
		 */
		if (ZEBRA_ROUTE_ISIS == d->proto)
			p->isis_z_area_id = d->proto_data.isis.z_area_id;

		if (CHECK_FLAG(p->flags, FAII_FLAG_SESSION_ID))
			/*
			 * Already recorded "ready" for this igp+instance: IGP
			 * instance must have restarted, so we must
			 * reset all of the corresponding candidate paths.
			 */
			need_clear = true;
		else
			/*
			 * session ID not yet set, so this igp instance
			 * was a stub created by candidate path(s) awaiting
			 * startup of the IGP instance. Mark ready.
			 */
			SET_FLAG(p->flags, FAII_FLAG_SESSION_ID);

		/*
		 * Iterate over flex-algo endpoints and find those
		 * that match this igp-ready (proto, vrf, instance, area-tag).
		 *
		 * Since igp-ready should be very infrequent, it's
		 * OK that we don't optimize this endpoint lookup.
		 */
		struct flex_algo_endpoint *f;

		frr_each (fae, &_faehash, f) {
			if (f->igp_proto != di->proto)
				continue;
			if (f->vrf_id != d->vrf_id)
				continue;
			if (f->igp_instance != di->instance)
				continue;
			if (ZEBRA_ROUTE_ISIS == di->proto) {
				if (strcmp(d->proto_data.isis.area_tag,
					   f->isis_area))
					continue;
			}
			struct candidate_entry *ce;

			frr_each (cand, &f->candidates, ce) {
				struct srte_candidate *c;

				c = ce->candidate;
				assert(SRTE_CANDIDATE_TYPE_FLEX_ALGO
				       == c->type);

				if (need_clear && c->lsp->segment_list) {
					SET_FLAG(c->lsp->segment_list->flags,
						 F_SEGMENT_LIST_DELETED);
					srte_segment_list_del(
						c->lsp->segment_list);
					c->lsp->segment_list = NULL;
				}
				/*
				 * issue FAE registration requests for all
				 * candidate paths that have this igp instance
				 */
				_register(c, p);
			}
		}
		srte_apply_changes();
	} else {
		fa_igp_add(di->proto, di->instance, d->vrf_id,
			   d->proto_data.isis.area_tag, true, di->session_id,
			   (ZEBRA_ROUTE_ISIS == d->proto),
			   d->proto_data.isis.z_area_id);
	}
}

void fa_igp_handle_notready(struct zapi_fae_daemon_id *di,
			    struct zapi_fae_igp_discriminator *d)
{
	struct flex_algo_igp_instance *p;

	/*
	 * Did we record this igp-ready previously?
	 */
	p = fa_igp_find_p(di->proto, di->instance, d->vrf_id, NULL,
			  d->proto_data.isis.z_area_id);

	/*
	 * if we don't have this instance recorded, nothing to do
	 */
	if (!p)
		return;

	/*
	 * If we didn't record "ready" for this instance,
	 * nothing to do
	 */
	if (!CHECK_FLAG(p->flags, FAII_FLAG_SESSION_ID))
		return;

	/*
	 * Iterate over flex-algo endpoints and find those
	 * that match this igp-ready (proto, vrf, instance, area-tag).
	 *
	 * Since igp-ready should be very infrequent, it's
	 * OK that we don't optimize this endpoint lookup.
	 */
	struct flex_algo_endpoint *f;

	frr_each (fae, &_faehash, f) {
		if (f->igp_proto != di->proto)
			continue;
		if (f->vrf_id != d->vrf_id)
			continue;
		if (f->igp_instance != di->instance)
			continue;
		if (ZEBRA_ROUTE_ISIS == d->proto) {
			if (strcmp(d->proto_data.isis.area_tag, f->isis_area))
				continue;
		}
		struct candidate_entry *ce;

		frr_each (cand, &f->candidates, ce) {
			struct srte_candidate *c;

			c = ce->candidate;
			assert(SRTE_CANDIDATE_TYPE_FLEX_ALGO == c->type);

			if (c->lsp->segment_list) {
				SET_FLAG(c->lsp->segment_list->flags,
					 F_SEGMENT_LIST_DELETED);
				srte_segment_list_del(c->lsp->segment_list);
				c->lsp->segment_list = NULL;
			}
		}
	}
	srte_apply_changes();
}

static void _fae_seglist_to_candidate(struct flex_algo_endpoint *f,
				      struct srte_candidate *candidate)
{
	if (candidate->lsp->segment_list) {
		srte_segment_list_del(candidate->lsp->segment_list);
		candidate->lsp->segment_list = NULL;
	}

	/*
	 * construct name of segment-list as:
	 * <candidate-path-name>-fa-p<candidate-path-preference>
	 */
	char *sname;
	struct srte_segment_list *segment_list = NULL;

	if (f->sid_list.label_num) {
		sname = asprintfrr(MTYPE_SEG_LIST_NAME, "%s-fa-p%u",
				   candidate->name, candidate->preference);
		segment_list = srte_segment_list_add(sname);
		XFREE(MTYPE_SEG_LIST_NAME, sname);
		segment_list->protocol_origin = candidate->protocol_origin;

		/* Not setting originator */

		SET_FLAG(segment_list->flags, F_SEGMENT_LIST_NEW);
		SET_FLAG(segment_list->flags, F_SEGMENT_LIST_MODIFIED);

		for (int i = 0; i < f->sid_list.label_num; ++i) {
			int index;
			struct srte_segment_entry *segment;

			/* create a segment-list using indexes going from 10 to 10 */
			index = (i + 1) * 10;

			segment = srte_segment_entry_add(segment_list, index);
			segment->sid_value = f->sid_list.labels[i];
			SET_FLAG(segment->segment_list->flags,
				 F_SEGMENT_LIST_MODIFIED);
		}
	}

	candidate->lsp->segment_list = segment_list;
	SET_FLAG(candidate->flags, F_CANDIDATE_MODIFIED);
}

void fa_candidate_endpoint_add(struct srte_candidate *candidate)
{
	assert(SRTE_CANDIDATE_TYPE_FLEX_ALGO == candidate->type);
	assert(!CHECK_FLAG(candidate->flags, F_CANDIDATE_FLEX_ALGO_REGISTERED));

	struct flex_algo_endpoint *f;

	f = XCALLOC(MTYPE_FLEX_ALGO_ENDPOINT,
		    sizeof(struct flex_algo_endpoint));
	f->algorithm = candidate->flex_algo_number;
	f->endpoint = candidate->policy->endpoint;

	if (CHECK_FLAG(candidate->flags,
		       F_CANDIDATE_FLEX_ALGO_IGP_USE_DEFAULTS)) {

		if (!_igp_defaults_valid()) {
			FA_DEBUG(
				"%s: endpoint %pIA: defaults invalid, skip reg",
				__func__, &candidate->policy->endpoint);
			XFREE(MTYPE_FLEX_ALGO_ENDPOINT, f);
			return;
		}
		f->igp_proto = _igp_defaults.igp_proto;
		f->vrf_id = _igp_defaults.igp_vrf_id;
		f->igp_instance = _igp_defaults.igp_instance;
		if (ZEBRA_ROUTE_ISIS == f->igp_proto)
			f->isis_area = XSTRDUP(MTYPE_ISIS_AREA_TAG,
					       _igp_defaults.isis_area);
	} else {

		f->igp_proto = candidate->fa_igp_config.proto;
		f->vrf_id = candidate->fa_igp_config.vrf_id;
		f->igp_instance = candidate->fa_igp_config.instance;

		if (ZEBRA_ROUTE_ISIS == f->igp_proto)
			f->isis_area =
				XSTRDUP(MTYPE_ISIS_AREA_TAG,
					candidate->fa_igp_config.isis_area);
	}

	/* clang-format off */
	FA_DEBUG("%s: endpoint %pIA, algo %u, proto %u, inst %u, vrf_id %u",
		__func__,
		&f->endpoint,
		f->algorithm,
		f->igp_proto,
		f->igp_instance,
		f->vrf_id);
	/* clang-format on */

	if (ZEBRA_ROUTE_ISIS == f->igp_proto)
		FA_DEBUG("    area-tag %s", f->isis_area);

	/*
	 * If it already exists, we get back pointer to list's copy
	 */
	struct flex_algo_endpoint *f_dup;

	f_dup = fae_add(&_faehash, f);

	if (f_dup) {
		XFREE(MTYPE_ISIS_AREA_TAG, f->isis_area);
		XFREE(MTYPE_FLEX_ALGO_ENDPOINT, f);
		f = f_dup;
	} else {
		/*
		 * initialize endpoint
		 */
		cand_init(&f->candidates);
		f->sid_list.type = ZEBRA_LSP_NONE;

		/*
		 * register endpoint with igp
		 */
		struct flex_algo_igp_instance *p;

		/* clang-format off */
		if ((p = fa_igp_find_ready_p(
			f->igp_proto,
			f->igp_instance,
			f->vrf_id,
			f->isis_area))) {

			FA_DEBUG("%s: found ready IGP", __func__);
			_register(candidate, p);
		} else {
			FA_DEBUG("%s: Didn't find ready IGP", __func__);
			/* add not-ready IGP entry */
			fa_igp_add(f->igp_proto, f->igp_instance, f->vrf_id,
				   f->isis_area, false, 0, false, 0);
		}
		/* clang-format on */
	}

	/*
	 * add candidate to list
	 */
	struct candidate_entry *c;
	struct candidate_entry *c_dup;

	c = XCALLOC(MTYPE_CANDIDATE_ENTRY, sizeof(struct candidate_entry));
	c->candidate = candidate;

	c_dup = cand_add(&f->candidates, c);

	if (c_dup) {
		XFREE(MTYPE_CANDIDATE_ENTRY, c);
	}

	srte_candidate_set_fa_igp_state(candidate, f->igp_proto,
					f->igp_instance, f->vrf_id,
					f->isis_area);

	/*
	 * This flag indicates that:
	 *
	 * - candidate is represented in the fae (flex algo endpoint) table
	 *
	 * - candidate's fa_igp_state contains the IGP values used to
	 *   index candidate in the fae table
	 */
	SET_FLAG(candidate->flags, F_CANDIDATE_FLEX_ALGO_REGISTERED);


	/*
	 * if we have a sid-list result from igp already,
	 * copy it to this candidate
	 */
	if (f->sid_list.type != ZEBRA_LSP_NONE && f->sid_list.label_num != 0) {

		_fae_seglist_to_candidate(f, candidate);

		/*
		 * northbound config infrastructure will call
		 * srte_apply_changes() afterward
		 */
	}
}

void fa_candidate_endpoint_del(struct srte_candidate *c)
{
	assert(SRTE_CANDIDATE_TYPE_FLEX_ALGO == c->type);
	assert(CHECK_FLAG(c->flags, F_CANDIDATE_FLEX_ALGO_REGISTERED));

	/*
	 * Find endpoint entry
	 */
	struct flex_algo_endpoint f_search = {
		.algorithm = c->flex_algo_number,
		.endpoint = c->policy->endpoint,

		.igp_proto = c->fa_igp_state.proto,
		.igp_instance = c->fa_igp_state.instance,
		.vrf_id = c->fa_igp_state.vrf_id,
	};
	if (ZEBRA_ROUTE_ISIS == c->fa_igp_state.proto) {
		f_search.isis_area = c->fa_igp_state.isis_area;
	}

	struct flex_algo_endpoint *f;

	f = fae_find(&_faehash, &f_search);
	assert(f);

	/*
	 * Find candidate in endpoint entry's list and remove.
	 * if candidate list becomes empty, remove endpoint
	 * and unregister.
	 */
	struct candidate_entry c_search = {
		.candidate = c,
	};

	struct candidate_entry *c_result;

	c_result = cand_find(&f->candidates, &c_search);
	assert(c_result);

	cand_del(&f->candidates, c_result);
	XFREE(MTYPE_CANDIDATE_ENTRY, c_result);

	UNSET_FLAG(c->flags, F_CANDIDATE_FLEX_ALGO_REGISTERED);

	if (!cand_count(&f->candidates)) {
		struct flex_algo_igp_instance *p;

		assert(c->fa_igp_state.isis_area);
		p = fa_igp_find_p(
			c->fa_igp_state.proto, c->fa_igp_state.instance,
			c->fa_igp_state.vrf_id, c->fa_igp_state.isis_area, 0);
		if (p)
			_unregister(c, p);

		fae_del(&_faehash, f);
		XFREE(MTYPE_ISIS_AREA_TAG, f->isis_area);
		XFREE(MTYPE_FLEX_ALGO_ENDPOINT, f);
	}
	/*
	 * northbound config infrastructure will call
	 * srte_apply_changes() afterward
	 */
}

void fa_handle_update(struct zapi_fae_daemon_id *di,
		      struct zapi_fae_igp_discriminator *d,
		      struct zapi_fae_query *query,
		      struct zapi_fae_answer *answer)
{
	if (0 != answer->sid_format) {
		zlog_err("%s: sid_format: expected 0, got %u (dropping)",
			 __func__, answer->sid_format);
		return;
	}

	/*
	 * Find ET entry with matching endpoint
	 */

	struct flex_algo_endpoint f_search = {
		.algorithm = query->algorithm,
		.endpoint = query->endpoint,
		.igp_proto = di->proto,
		.igp_instance = di->instance,
		.vrf_id = d->vrf_id,
	};
	if (ZEBRA_ROUTE_ISIS == d->proto) {
		struct flex_algo_igp_instance *igp;

		/*
		 * Get the isis area-tag string by looking up via
		 * the message's z_area_id in our IGP table
		 */
		igp = fa_igp_find_p(di->proto, di->instance, d->vrf_id, NULL,
				    d->proto_data.isis.z_area_id);
		if (!igp) {
			/*
			 * unknown, shouldn't happen
			 */
			zlog_err("%s: can't find igp isis with z_area_id 0x%x",
				 __func__, d->proto_data.isis.z_area_id);
			goto fail_unregister;
		}

		f_search.isis_area = igp->isis_area;
	}
	struct flex_algo_endpoint *f;

	f = fae_find(&_faehash, &f_search);
	if (!f) {
		char *sAT = NULL;

		if (ZEBRA_ROUTE_ISIS == d->proto)
			sAT = d->proto_data.isis.area_tag;
		zlog_err(
			"%s: endpoint not found (addr %pIA, vrf %u, proto %s, alg %u, inst %u%s",
			__func__, &query->endpoint, d->vrf_id,
			zebra_route_string(di->proto), query->algorithm,
			di->instance, (sAT ? sAT : ""));
		goto fail_unregister;
	}

	/*
	 * Compare update's sid-list with f's cached sid-list
	 */
	bool different = false;

	if (answer->sid_list.label_num != f->sid_list.label_num)
		different = true;
	else {
		FA_DEBUG("%s: label_num %u", __func__,
			 answer->sid_list.label_num);
		for (uint8_t i = 0; i < answer->sid_list.label_num; ++i) {
			if (answer->sid_list.labels[i]
			    != f->sid_list.labels[i]) {
				different = true;
				break;
			}
		}
	}

	FA_DEBUG("%s: sid-lists are %s", __func__,
		 (different ? "different" : "the same"));

	if (different) {
		/*
		 * update our cached copy
		 * "valid" means "f->sid_list.label_num != 0" AND
		 * "f->sid_list.type != ZEBRA_LSP_NONE"
		 */
		f->sid_list = answer->sid_list;

		/*
		 * Iterate over corresponding candidates and update
		 * their sid-lists
		 */
		struct candidate_entry *ce;

		frr_each (cand, &f->candidates, ce) {
			struct srte_candidate *c;

			c = ce->candidate;
			assert(SRTE_CANDIDATE_TYPE_FLEX_ALGO == c->type);
			_fae_seglist_to_candidate(f, c);
		}
		fa_apply_changes();
	}
	return;

fail_unregister:
	/* clang-format off */
	path_zebra_fae_register(
		false,
		&query->endpoint,
		query->algorithm,
		di->proto,
		di->instance,
		di->session_id,
		d->vrf_id,
		d->proto_data.isis.z_area_id);
	/* clang-format on */
}

/*
 * Event handlers triggered by timers after srte_policy_apply_changes()
 * is called.
 */

static int _fa_candidate_updated_hnd(struct srte_candidate *candidate)
{
	if (SRTE_CANDIDATE_TYPE_FLEX_ALGO != candidate->type)
		return 0;

	FA_DEBUG("%s: is flex-algo type", __func__);

	if (CHECK_FLAG(candidate->flags, F_CANDIDATE_HAS_FLEX_ALGO_NUMBER)) {
		FA_DEBUG("%s: has flex-algo number", __func__);

		if (CHECK_FLAG(candidate->flags,
			       F_CANDIDATE_FLEX_ALGO_REGISTERED)) {

			FA_DEBUG("%s: already registered, skip", __func__);
			return 0;
		}

		/*
		 * Not yet registered.
		 *
		 * add to flex-algo endpoint tracking
		 */
		FA_DEBUG("%s: not yet registered, proceed", __func__);
		fa_candidate_endpoint_add(candidate);
	}
	return 0;
}

static int _fa_candidate_created_hnd(struct srte_candidate *candidate)
{
	return _fa_candidate_updated_hnd(candidate);
}

static int _fa_candidate_removed_hnd(struct srte_candidate *candidate)
{
	if (SRTE_CANDIDATE_TYPE_FLEX_ALGO != candidate->type)
		return 0;

	if (CHECK_FLAG(candidate->flags, F_CANDIDATE_HAS_FLEX_ALGO_NUMBER)) {
		if (CHECK_FLAG(candidate->flags,
			       F_CANDIDATE_FLEX_ALGO_REGISTERED)) {

			FA_DEBUG("%s: calling fa_candidate_endpoint_del",
				 __func__);
			fa_candidate_endpoint_del(candidate);
		}
	}
	return 0;
}

void path_flex_algo_init(void)
{
	_igp_defaults.igp_proto = ZEBRA_ROUTE_ISIS;
	_igp_defaults.igp_instance = 0;
	_igp_defaults.igp_vrf_id = VRF_DEFAULT;
	_igp_defaults.isis_area = NULL;

	fae_init(&_faehash);

	hook_register(pathd_candidate_created, _fa_candidate_created_hnd);
	hook_register(pathd_candidate_updated, _fa_candidate_updated_hnd);
	hook_register(pathd_candidate_removed, _fa_candidate_removed_hnd);
}

void path_flex_algo_finish(void)
{
	unsigned int igp_instance_count = 0;
	unsigned int area_string_count = 0;
	struct flex_algo_igp_instance *fa_igp_instance;

	FA_DEBUG("%s: fae_count is %lu", __func__, (long unsigned int) fae_count(&_faehash));
	fae_fini(&_faehash);

	if (_igp_defaults.isis_area) {
		FA_DEBUG("%s: freeing _igp_defaults.isis_area", __func__);
		XFREE(MTYPE_ISIS_AREA_TAG, _igp_defaults.isis_area);
		_igp_defaults.isis_area = NULL;
	}

	if (_igp_instance) {
		for (; igp_instance_count < vector_active(_igp_instance);
		     ++igp_instance_count) {

			fa_igp_instance =
				vector_slot(_igp_instance, igp_instance_count);
			if (!fa_igp_instance)
				continue;
			if (ZEBRA_ROUTE_ISIS == fa_igp_instance->proto) {
				XFREE(MTYPE_ISIS_AREA_TAG,
				      fa_igp_instance->isis_area);
				fa_igp_instance->isis_area = NULL;
				++area_string_count;
			}
			XFREE(MTYPE_FLEX_ALGO_IGP_INSTANCE, fa_igp_instance);
		}
		if (igp_instance_count) {
			FA_DEBUG("%s: freed %u flex_algo_igp_instance structs",
				 __func__, igp_instance_count);
			if (area_string_count)
				FA_DEBUG("%s: freed %u isis_area strings",
					 __func__, area_string_count);
		}
		vector_free(_igp_instance);
		FA_DEBUG("%s: freed _igp_instance vector", __func__);
	}
}
