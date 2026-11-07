// SPDX-License-Identifier: GPL-2.0-or-later

#include "zebra.h"
#include "hash.h"
#include "json.h"
#include "libfrr.h"
#include "nhrpd.h"

static unsigned int nhrp_reqid_key(const void *data)
{
	const struct nhrp_reqid *r = data;
	return r->request_id;
}

static bool nhrp_reqid_cmp(const void *data, const void *key)
{
	const struct nhrp_reqid *a = data, *b = key;

	return a->request_id == b->request_id;
}

static void nhrp_reqid_state_read(struct nhrp_reqid_pool *p)
{
	struct json_object *json;
	struct json_object *json_reqid;

	json = frr_daemon_state_load();
	json_object_object_get_ex(json, "reqid", &json_reqid);
	if (json_reqid) {
		p->next_request_id = json_object_get_uint64(json_reqid);
		if (p->next_request_id == 0)
			p->next_request_id = 1;
	}
	json_object_put(json);
}

static void nhrp_reqid_state_write(uint32_t next)
{
	struct json_object *json;
	struct json_object *json_reqid;

	json = frr_daemon_state_load();
	json_reqid = json_object_new_uint64(next);
	json_object_object_add(json, "reqid", json_reqid);
	frr_daemon_state_save(&json);
}

uint32_t nhrp_reqid_alloc(struct nhrp_reqid_pool *p, struct nhrp_reqid *r,
			  void (*cb)(struct nhrp_reqid *, void *))
{
	if (!p->reqid_hash) {
		p->reqid_hash = hash_create(nhrp_reqid_key, nhrp_reqid_cmp,
					    "NHRP reqid Hash");
		p->next_request_id = 1;
		if (p->persist)
			nhrp_reqid_state_read(p);
	}

	if (r->cb != cb) {
		r->request_id = p->next_request_id;
		if (++p->next_request_id == 0)
			p->next_request_id = 1;
		r->cb = cb;
		(void)hash_get(p->reqid_hash, r, hash_alloc_intern);
		/* RFC 2332 5.2.3: keep the request ID in nonvolatile
		 * storage; persist the next ID after each allocation so
		 * that a restart never hands out a request ID that has
		 * already been sent to the NHS.
		 */
		if (p->persist)
			nhrp_reqid_state_write(p->next_request_id);
	}
	return r->request_id;
}

void nhrp_reqid_free(struct nhrp_reqid_pool *p, struct nhrp_reqid *r)
{
	if (r->cb) {
		hash_release(p->reqid_hash, r);
		r->cb = NULL;
	}
}

struct nhrp_reqid *nhrp_reqid_lookup(struct nhrp_reqid_pool *p, uint32_t reqid)
{
	struct nhrp_reqid key;
	if (!p->reqid_hash)
		return 0;
	key.request_id = reqid;
	return hash_lookup(p->reqid_hash, &key);
}

void nhrp_reqid_terminate(struct nhrp_reqid_pool *p)
{
	if (!p)
		return;

	hash_clean_and_free(&p->reqid_hash, NULL);
	p->next_request_id = 0;
}
