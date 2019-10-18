/*
 * Copyright (c) 2019  David Lamparter, for NetDEF, Inc.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* C++ called, they want their templates back */
#define item		concat(item_, TYPE)
#define itm		concat(itm_, TYPE)
#define head		concat(head_, TYPE)
#define list		concat(TYPE, )
#define list_head	concat(TYPE, _head)
#define list_item	concat(TYPE, _item)
#define list_cmp	concat(TYPE, _cmp)
#define list_hash	concat(TYPE, _hash)
#define list_init	concat(TYPE, _init)
#define list_fini	concat(TYPE, _fini)
#define list_first	concat(TYPE, _first)
#define list_next	concat(TYPE, _next)
#define list_next_safe	concat(TYPE, _next_safe)
#define list_count	concat(TYPE, _count)
#define list_add	concat(TYPE, _add)
#define list_add_head	concat(TYPE, _add_head)
#define list_add_tail	concat(TYPE, _add_tail)
#define list_add_after	concat(TYPE, _add_after)
#define list_find	concat(TYPE, _find)
#define list_find_lt	concat(TYPE, _find_lt)
#define list_find_gteq	concat(TYPE, _find_gteq)
#define list_del	concat(TYPE, _del)
#define list_pop	concat(TYPE, _pop)

#define ts_hash		concat(ts_hash_, TYPE)

#ifndef REALTYPE
#define REALTYPE TYPE
#endif

PREDECL(REALTYPE, list)
struct item {
	uint64_t val;
	struct list_item itm;
	int scratchpad;
};

#if IS_SORTED(REALTYPE)
static int list_cmp(const struct item *a, const struct item *b);

#if IS_HASH(REALTYPE)
static uint32_t list_hash(const struct item *a);
DECLARE(REALTYPE, list, struct item, itm, list_cmp, list_hash)

static uint32_t list_hash(const struct item *a)
{
#ifdef SHITTY_HASH
	/* crappy hash to get some hash collisions */
	return a->val ^ (a->val << 29) ^ 0x55AA0000U;
#else
	return jhash_1word(a->val, 0xdeadbeef);
#endif
}

#else
DECLARE(REALTYPE, list, struct item, itm, list_cmp)
#endif

static int list_cmp(const struct item *a, const struct item *b)
{
	if (a->val > b->val)
		return 1;
	if (a->val < b->val)
		return -1;
	return 0;
}

#else /* !IS_SORTED */
DECLARE(REALTYPE, list, struct item, itm)
#endif

#define NITEM 10000
struct item itm[NITEM];
static struct list_head head = concat(INIT_, REALTYPE)(head);

static void ts_hash(const char *text, const char *expect)
{
	int64_t us = monotime_since(&ref, NULL);
	SHA256_CTX ctx;
	struct item *item;
	unsigned i = 0;
	uint8_t hash[32];
	char hashtext[65];
	uint32_t count;

	count = htonl(list_count(&head));

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, &count, sizeof(count));

	frr_each (list, &head, item) {
		struct {
			uint32_t val_upper, val_lower, index;
		} hashitem = {
			htonl(item->val >> 32),
			htonl(item->val & 0xFFFFFFFFULL),
			htonl(i),
		};
		SHA256_Update(&ctx, &hashitem, sizeof(hashitem));
		i++;
		assert(i < count);
	}
	SHA256_Final(hash, &ctx);

	for (i = 0; i < sizeof(hash); i++)
		sprintf(hashtext + i * 2, "%02x", hash[i]);

	printf("%7"PRId64"us  %-25s %s%s\n", us, text,
	       expect ? " " : "*", hashtext);
	if (expect && strcmp(expect, hashtext)) {
		printf("%-21s %s\n", "EXPECTED:", expect);
		assert(0);
	}
	monotime(&ref);
}
/* hashes will have different item ordering */
#if IS_HASH(REALTYPE) || IS_HEAP(REALTYPE)
#define ts_hashx(pos, csum) ts_hash(pos, NULL)
#else
#define ts_hashx(pos, csum) ts_hash(pos, csum)
#endif

static void concat(test_, TYPE)(void)
{
	size_t i, j, k, l;
	struct prng *prng;
	struct item *item, *prev __attribute__((unused));
	struct item dummy __attribute__((unused));

	memset(itm, 0, sizeof(itm));
	for (i = 0; i < NITEM; i++)
		itm[i].val = i;

	printf("%s start\n", str(TYPE));
	ts_start();

	list_init(&head);
	assert(list_first(&head) == NULL);

	ts_hash("init", "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119");

#if IS_SORTED(REALTYPE)
	prng = prng_new(0);
	k = 0;
	for (i = 0; i < NITEM; i++) {
		j = prng_rand(prng) % NITEM;
		if (itm[j].scratchpad == 0) {
			list_add(&head, &itm[j]);
			itm[j].scratchpad = 1;
			k++;
		}
#if !IS_HEAP(REALTYPE)
		else
			assert(list_add(&head, &itm[j]) == &itm[j]);
#endif
	}
	assert(list_count(&head) == k);
	assert(list_first(&head) != NULL);
	ts_hashx("fill", "a538546a6e6ab0484e925940aa8dd02fd934408bbaed8cb66a0721841584d838");

	k = 0;
	prev = NULL;
	frr_each(list, &head, item) {
#if IS_HASH(REALTYPE) || IS_HEAP(REALTYPE)
		/* hash table doesn't give sorting */
		(void)prev;
#else
		assert(!prev || prev->val < item->val);
#endif
		prev = item;
		k++;
	}
	assert(list_count(&head) == k);
	ts_ref("walk");

#if IS_UNIQ(REALTYPE)
	prng_free(prng);
	prng = prng_new(0);

	for (i = 0; i < NITEM; i++) {
		j = prng_rand(prng) % NITEM;
		dummy.val = j;
		assert(list_find(&head, &dummy) == &itm[j]);
	}
	ts_ref("find");

	for (i = 0; i < NITEM; i++) {
		j = prng_rand(prng) % NITEM;
		memset(&dummy, 0, sizeof(dummy));
		dummy.val = j;
		if (itm[j].scratchpad)
			assert(list_add(&head, &dummy) == &itm[j]);
		else {
			assert(list_add(&head, &dummy) == NULL);
			assert(list_del(&head, &dummy) != NULL);
		}
	}
	ts_hashx("add-dup", "a538546a6e6ab0484e925940aa8dd02fd934408bbaed8cb66a0721841584d838");

#elif IS_HEAP(REALTYPE)
	/* heap - partially sorted. */
	prev = NULL;
	l = k / 2;
	for (i = 0; i < l; i++) {
		item = list_pop(&head);
		if (prev)
			assert(prev->val < item->val);
		item->scratchpad = 0;
		k--;
		prev = item;
	}
	ts_hash("pop", NULL);

#else /* !IS_UNIQ(REALTYPE) && !IS_HEAP(REALTYPE) */
	for (i = 0; i < NITEM; i++) {
		j = prng_rand(prng) % NITEM;
		memset(&dummy, 0, sizeof(dummy));
		dummy.val = j;

		list_add(&head, &dummy);
		if (itm[j].scratchpad) {
			struct item *lt, *gteq, dummy2;

			assert(list_next(&head, &itm[j]) == &dummy ||
				list_next(&head, &dummy) == &itm[j]);

			memset(&dummy2, 0, sizeof(dummy));
			dummy2.val = j;
			lt = list_find_lt(&head, &dummy2);
			gteq = list_find_gteq(&head, &dummy2);

			assert(gteq == &itm[j] || gteq == &dummy);
			if (lt)
				assert(list_next(&head, lt) == &itm[j] ||
					list_next(&head, lt) == &dummy);
			else
				assert(list_first(&head) == &itm[j] ||
					list_first(&head) == &dummy);
		} else if (list_next(&head, &dummy))
			assert(list_next(&head, &dummy)->val > j);
		assert(list_del(&head, &dummy) != NULL);
	}
	ts_hash("add-dup+find_{lt,gteq}", "a538546a6e6ab0484e925940aa8dd02fd934408bbaed8cb66a0721841584d838");
#endif
#if !IS_HASH(REALTYPE) && !IS_HEAP(REALTYPE)
	prng_free(prng);
	prng = prng_new(123456);

	l = 0;
	for (i = 0; i < NITEM; i++) {
		struct item *lt, *gteq, *tmp;

		j = prng_rand(prng) % NITEM;
		dummy.val = j;

		lt = list_find_lt(&head, &dummy);
		gteq = list_find_gteq(&head, &dummy);

		if (lt) {
			assert(lt->val < j);
			tmp = list_next(&head, lt);
			assert(tmp == gteq);
			assert(!tmp || tmp->val >= j);
		} else
			assert(gteq == list_first(&head));

		if (gteq)
			assert(gteq->val >= j);
	}
	ts_ref("find_{lt,gteq}");
#endif /* !IS_HASH */

	prng_free(prng);
	prng = prng_new(0);

	l = 0;
	for (i = 0; i < NITEM; i++) {
		(void)prng_rand(prng);
		j = prng_rand(prng) % NITEM;
		if (itm[j].scratchpad == 1) {
			assert(list_del(&head, &itm[j]) != NULL);
			itm[j].scratchpad = 0;
			l++;
		}
	}
	assert(l + list_count(&head) == k);
	ts_hashx("del", "cb2e5d80f08a803ef7b56c15e981b681adcea214bebc2f55e12e0bfb242b07ca");

	frr_each_safe(list, &head, item) {
		assert(item->scratchpad != 0);

		if (item->val & 1) {
			assert(list_del(&head, item) != NULL);
			item->scratchpad = 0;
			l++;
		}
	}
	assert(l + list_count(&head) == k);
	ts_hashx("frr_each_safe+del", "e0beb71dd963a75af05b722b8e71b61b304587d860c8accdc4349067542b86bb");

#else /* !IS_SORTED */
	prng = prng_new(0);
	k = 0;
	for (i = 0; i < NITEM; i++) {
		j = prng_rand(prng) % NITEM;
		if (itm[j].scratchpad == 0) {
			list_add_tail(&head, &itm[j]);
			itm[j].scratchpad = 1;
			k++;
		}
	}
	assert(list_count(&head) == k);
	assert(list_first(&head) != NULL);
	ts_hash("fill / add_tail", "eabfcf1413936daaf20965abced95762f45110a6619b84aac7d38481bce4ea19");

	for (i = 0; i < NITEM / 2; i++) {
		j = prng_rand(prng) % NITEM;
		if (itm[j].scratchpad == 1) {
			assert(list_del(&head, &itm[j]) != NULL);
			itm[j].scratchpad = 0;
			k--;
		}
	}
	ts_hash("del-prng", "86d568a95eb429dab3162976c5a5f3f75aabc835932cd682aa280b6923549564");

	l = 0;
	while ((item = list_pop(&head))) {
		assert(item->scratchpad != 0);

		item->scratchpad = 0;
		l++;
	}
	assert(l == k);
	assert(list_count(&head) == 0);
	assert(list_first(&head) == NULL);
	ts_hash("pop", "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119");

	prng_free(prng);
	prng = prng_new(0x1e5a2d69);

	k = 0;
	for (i = 0; i < NITEM; i++) {
		j = prng_rand(prng) % NITEM;
		if (itm[j].scratchpad == 0) {
			list_add_head(&head, &itm[j]);
			itm[j].scratchpad = 1;
			k++;
		}
	}
	assert(list_count(&head) == k);
	assert(list_first(&head) != NULL);
	ts_hash("fill / add_head", "3084d8f8a28b8c756ccc0a92d60d86f6d776273734ddc3f9e1d89526f5ca2795");

	for (i = 0; i < NITEM / 2; i++) {
		j = prng_rand(prng) % NITEM;
		if (itm[j].scratchpad == 1) {
			assert(list_del(&head, &itm[j]) != NULL);
			itm[j].scratchpad = 0;
			k--;
		}
	}
	ts_hash("del-prng", "dc916fa7ea4418792c7c8232d74df2887f9975ead4222f4b977be6bc0b52285e");

	l = 0;
	while ((item = list_pop(&head))) {
		assert(item->scratchpad != 0);

		item->scratchpad = 0;
		l++;
	}
	assert(l == k);
	assert(list_count(&head) == 0);
	assert(list_first(&head) == NULL);
	ts_hash("pop", "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119");

	prng_free(prng);
	prng = prng_new(0x692d1e5a);

	k = 0;
	for (i = 0; i < NITEM; i++) {
		j = prng_rand(prng) % NITEM;
		if (itm[j].scratchpad == 0) {
			if (prng_rand(prng) & 1) {
				list_add_tail(&head, &itm[j]);
			} else {
				list_add_head(&head, &itm[j]);
			}
			itm[j].scratchpad = 1;
			k++;
		}
	}
	assert(list_count(&head) == k);
	assert(list_first(&head) != NULL);
	ts_hash("fill / add_{head,tail}", "93fa180a575c96e4b6c3775c2de7843ee3254dd6ed5af699bbe155f994114b06");

	for (i = 0; i < NITEM * 3; i++) {
		int op = prng_rand(prng);
		j = prng_rand(prng) % NITEM;

		if (op & 1) {
			/* delete or pop */
			if (op & 2) {
				item = list_pop(&head);
				if (!item)
					continue;
			} else {
				item = &itm[j];
				if (item->scratchpad == 0)
					continue;
				assert(list_del(&head, item) != NULL);
			}
			item->scratchpad = 0;
			k--;
		} else {
			item = &itm[j];
			if (item->scratchpad != 0)
				continue;

			item->scratchpad = 1;
			k++;

			switch ((op >> 1) & 1) {
			case 0:
				list_add_head(&head, item);
				break;
			case 1:
				list_add_tail(&head, item);
				break;
			default:
				assert(0);
			}
		}
	}
	assert(list_count(&head) == k);
	assert(list_first(&head) != NULL);
	ts_hash("prng add/del", "4909f31d06bb006efca4dfeebddb8de071733ddf502f89b6d532155208bbc6df");

#if !IS_ATOMIC(REALTYPE)
	/* variant with add_after */

	for (i = 0; i < NITEM * 3; i++) {
		int op = prng_rand(prng);
		j = prng_rand(prng) % NITEM;

		if (op & 1) {
			/* delete or pop */
			if (op & 2) {
				item = list_pop(&head);
				if (!item)
					continue;
			} else {
				item = &itm[j];
				if (item->scratchpad == 0)
					continue;
				assert(list_del(&head, item) != NULL);
			}
			item->scratchpad = 0;
			k--;
		} else {
			item = &itm[j];
			if (item->scratchpad != 0)
				continue;

			item->scratchpad = 1;
			k++;

			switch ((op >> 1) & 3) {
			case 0:
				list_add_head(&head, item);
				break;
			case 1:
				list_add_tail(&head, item);
				break;
			case 2:
			case 3:
				prev = NULL;
				l = 0;
				do {
					j = prng_rand(prng) % NITEM;
					prev = &itm[j];
					if (prev->scratchpad == 0
					    || prev == item)
						prev = NULL;
					l++;
				} while (!prev && l < 10);
				list_add_after(&head, prev, item);
				break;
			default:
				assert(0);
			}
		}
	}
	assert(list_count(&head) == k);
	assert(list_first(&head) != NULL);
	ts_hash("prng add/after/del", "84c5fc83294eabebb9808ccbba32a303c4fca084db87ed1277d2bae1f8c5bee4");
#endif

	l = 0;
#endif

	while ((item = list_pop(&head))) {
		assert(item->scratchpad != 0);

		item->scratchpad = 0;
		l++;
	}
	assert(l == k);
	assert(list_count(&head) == 0);
	assert(list_first(&head) == NULL);
	ts_hash("pop", "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119");

	list_fini(&head);
	ts_ref("fini");
	ts_end();
	printf("%s end\n", str(TYPE));
}

#undef ts_hashx

#undef item
#undef itm
#undef head
#undef list
#undef list_head
#undef list_item
#undef list_cmp
#undef list_hash
#undef list_init
#undef list_fini
#undef list_first
#undef list_next
#undef list_next_safe
#undef list_count
#undef list_add
#undef list_add_head
#undef list_add_tail
#undef list_add_after
#undef list_find
#undef list_find_lt
#undef list_find_gteq
#undef list_del
#undef list_pop

#undef REALTYPE
#undef TYPE
