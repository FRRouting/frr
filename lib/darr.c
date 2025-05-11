// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * June 23 2023, Christian Hopps <chopps@labn.net>
 *
 * Copyright (c) 2023, LabN Consulting, L.L.C.
 *
 */
#include <zebra.h>
#include "darr.h"
#include "memory.h"
#include "printfrr.h"

DEFINE_MTYPE(LIB, DARR, "Dynamic Array");
DEFINE_MTYPE(LIB, DARR_STR, "Dynamic Array String");

static uint _msb(uint count)
{
	uint bit = 0;
	int msb = 0;

	while (count) {
		if (count & 1)
			msb = bit;
		count >>= 1;
		bit += 1;
	}
	return msb;
}

static uint darr_next_count(uint count, size_t esize)
{
	uint ncount;

	if (esize > sizeof(long long) && count == 1)
		/* treat like a pointer */
		ncount = 1;
	else {
		uint msb = _msb(count);

		ncount = 1ull << msb;
		/* if the users count wasn't a pow2 make it the next pow2. */
		if (ncount != count) {
			assert(ncount < count);
			ncount <<= 1;
			if (esize < sizeof(long long) && ncount < 8)
				ncount = 8;
		}
	}
	return ncount;
}

static size_t darr_size(uint count, size_t esize)
{
	return count * esize + sizeof(struct darr_metadata);
}

char *_darr__in_vsprintf(char **sp, bool concat, const char *fmt, va_list ap)
{
	size_t inlen = concat ? darr_strlen(*sp) : 0;
	size_t capcount = strlen(fmt) + MIN(inlen + 64, 128);
	ssize_t len;
	va_list ap_copy;

	darr_ensure_cap(*sp, capcount);

	if (!concat)
		darr_reset(*sp);

	/* code below counts on having a NUL terminated string */
	if (darr_len(*sp) == 0)
		*darr_append(*sp) = 0;
again:
	va_copy(ap_copy, ap);
	len = vsnprintfrr(darr_last(*sp), darr_avail(*sp) + 1, fmt, ap_copy);
	va_end(ap_copy);
	if (len < 0)
		darr_in_strcat(*sp, fmt);
	else if ((size_t)len <= darr_avail(*sp))
		_darr_len(*sp) += len;
	else {
		darr_ensure_cap(*sp, darr_len(*sp) + (size_t)len);
		goto again;
	}
	return *sp;
}

char *_darr__in_sprintf(char **sp, bool concat, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void)_darr__in_vsprintf(sp, concat, fmt, ap);
	va_end(ap);
	return *sp;
}


void *_darr__resize(void *a, uint count, size_t esize, struct memtype *mtype)
{
	uint ncount = darr_next_count(count, esize);
	size_t osz = (a == NULL) ? 0 : darr_size(darr_cap(a), esize);
	size_t sz = darr_size(ncount, esize);
	struct darr_metadata *dm;

	if (a) {
		dm = XREALLOC(_darr_meta(a)->mtype, _darr_meta(a), sz);
		if (sz > osz)
			memset((char *)dm + osz, 0, sz - osz);
	} else {
		dm = XCALLOC(mtype, sz);
		dm->mtype = mtype;
	}
	dm->cap = ncount;
	return (void *)(dm + 1);
}


void *_darr__insert_n(void *a, uint at, uint count, size_t esize, bool zero, struct memtype *mtype)
{
	struct darr_metadata *dm;
	uint olen, nlen;

	if (!a)
		a = _darr__resize(NULL, at + count, esize, mtype);
	dm = (struct darr_metadata *)a - 1;
	olen = dm->len;

	// at == 1
	// count == 100
	// olen == 2

	/* see if the user is expanding first using `at` */
	if (at >= olen)
		nlen = at + count;
	else
		nlen = olen + count;

	if (nlen > dm->cap) {
		a = _darr__resize(a, nlen, esize, mtype);
		dm = (struct darr_metadata *)a - 1;
	}

#define _a_at(i) ((char *)a + ((i)*esize))
	if (at < olen)
		memmove(_a_at(at + count), _a_at(at), esize * (olen - at));

	dm->len = nlen;

	if (zero) {
		if (at >= olen) {
			at -= olen;
			count += olen;
		}
		memset(_a_at(at), 0, esize * count);
	}

	return a;
#undef _a_at
}

int _darr_search_floor(const void *a, size_t esize, const void *key, bool *equal,
		       darr_search_cmpf cmpf)
{
	struct darr_metadata *dm;

	if (equal)
		*equal = false;

	if (!a)
		return -1;

	dm = (struct darr_metadata *)a - 1;

	int len = dm->len;
	int low = 0, high = len - 1;
	int floor = -1;

#define _a_at(i) ((void *)((char *)a + ((i)*esize)))
	while (low <= high) {
		int mid = low + (high - low) / 2;
		int cmp;

		if (cmpf)
			cmp = cmpf(_a_at(mid), key);
		else
			cmp = memcmp(_a_at(mid), key, esize);

		if (!cmp) {
			if (equal)
				*equal = true;
			return mid;
		} else if (cmp < 0) {
			floor = mid;
			low = mid + 1;
		} else {
			high = mid - 1;
		}
	}

	return floor;
#undef _a_at
}

int _darr_search(const void *a, size_t esize, const void *key, darr_search_cmpf cmpf)
{
	bool equal;
	int i;

	i = _darr_search_floor(a, esize, key, &equal, cmpf);
	if (!equal)
		return -1;
	return i;
}

uint _darr_search_ceil(const void *a, size_t esize, const void *key, bool *equal,
		       darr_search_cmpf cmpf)
{
	uint i;

	i = _darr_search_floor(a, esize, key, equal, cmpf);
	if (*equal)
		return i;
	return i + 1;
}

int darr_strings_cmp(const char **a, const char *key)
{
	return strcmp(*a, key);
}
