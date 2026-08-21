// SPDX-License-Identifier: GPL-2.0-or-later

#include "zebra.h"
#include <fcntl.h>
#include "hash.h"
#include "libfrr.h"
#include "printfrr.h"
#include "nhrpd.h"

/*
 * RFC 2332 5.2.3: the request ID for registrations must be kept in
 * nonvolatile storage, so that a client crash and re-registration
 * does not leave the NHS database inconsistent.  The RFC allows the
 * update to be batched; we persist the counter every
 * NHRP_REQID_PERSIST_BATCH allocations, and on a restart continue
 * past the reserved interval by adding the batch size to the stored
 * value before the first allocation.
 */
#define NHRP_REQID_PERSIST_BATCH 100
#define NHRP_REQID_STATE_FILE "%s/nhrpd-reqid"

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

static uint32_t nhrp_reqid_state_read(void)
{
	char path[PATH_MAX];
	uint32_t stored = 0;
	ssize_t len;
	int fd;

	snprintfrr(path, sizeof(path), NHRP_REQID_STATE_FILE, frr_runstatedir);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return 0;
	len = read(fd, &stored, sizeof(stored));
	close(fd);
	if (len != sizeof(stored))
		return 0;
	return ntohl(stored);
}

static void nhrp_reqid_state_write(uint32_t next)
{
	char path[PATH_MAX], tmp[PATH_MAX + 4];
	uint32_t val = htonl(next);
	ssize_t len;
	int fd;

	snprintfrr(path, sizeof(path), NHRP_REQID_STATE_FILE, frr_runstatedir);
	snprintfrr(tmp, sizeof(tmp), "%s.tmp", path);
	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0)
		return;
	len = write(fd, &val, sizeof(val));
	if (len == sizeof(val) && fsync(fd) == 0)
		rename(tmp, path);
	close(fd);
	if (len != sizeof(val))
		unlink(tmp);
}

uint32_t nhrp_reqid_alloc(struct nhrp_reqid_pool *p, struct nhrp_reqid *r,
			  void (*cb)(struct nhrp_reqid *, void *))
{
	if (!p->reqid_hash) {
		uint32_t stored = p->persist ? nhrp_reqid_state_read() : 0;

		p->reqid_hash = hash_create(nhrp_reqid_key, nhrp_reqid_cmp,
					    "NHRP reqid Hash");
		/* On a restart, continue past the interval that may
		 * have been used before the crash.
		 */
		p->next_request_id = stored ? stored + NHRP_REQID_PERSIST_BATCH : 1;
		p->persisted_next = stored ? stored : 1;
	}

	if (r->cb != cb) {
		/* Persist before the counter leaves the reserved
		 * interval, so that a crash at any point is followed by
		 * a restart that skips every request ID used so far.
		 */
		if (p->persist && p->next_request_id
		    == p->persisted_next + NHRP_REQID_PERSIST_BATCH) {
			p->persisted_next = p->next_request_id;
			nhrp_reqid_state_write(p->persisted_next);
		}
		r->request_id = p->next_request_id;
		if (++p->next_request_id == 0)
			p->next_request_id = 1;
		r->cb = cb;
		(void)hash_get(p->reqid_hash, r, hash_alloc_intern);
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
