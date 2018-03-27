#include "zebra.h"
#include "hash.h"
#include "nhrpd.h"

static unsigned int nhrp_reqid_key(void *data)
{
	struct nhrp_reqid *r = data;
	return r->request_id;
}

static int nhrp_reqid_cmp(const void *data, const void *key)
{
	const struct nhrp_reqid *a = data, *b = key;
	return a->request_id == b->request_id;
}

uint32_t nhrp_reqid_alloc(struct nhrp_reqid_pool *p, struct nhrp_reqid *r,
			  void (*cb)(struct nhrp_reqid *, void *))
{
	if (!p->reqid_hash) {
		p->reqid_hash = hash_create(nhrp_reqid_key, nhrp_reqid_cmp,
					    "NHRP reqid Hash");
		p->next_request_id = 1;
	}

	if (r->cb != cb) {
		r->request_id = p->next_request_id;
		if (++p->next_request_id == 0)
			p->next_request_id = 1;
		r->cb = cb;
		hash_get(p->reqid_hash, r, hash_alloc_intern);
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
