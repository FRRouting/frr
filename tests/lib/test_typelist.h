// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2019  David Lamparter, for NetDEF, Inc.
 */

/* C++ called, they want their templates back */
#define item		concat(item_, TYPE)
#define itm		concat(itm_, TYPE)
#define itmswap		concat(itmswap_, TYPE)
#define head		concat(head_, TYPE)
#define list		concat(TYPE, )
#define list_head	concat(TYPE, _head)
#define list_item	concat(TYPE, _item)
#define list_cmp	concat(TYPE, _cmp)
#define list_hash	concat(TYPE, _hash)
#define list_init	concat(TYPE, _init)
#define list_fini	concat(TYPE, _fini)
#define list_const_first concat(TYPE, _const_first)
#define list_first	concat(TYPE, _first)
#define list_const_next	concat(TYPE, _const_next)
#define list_next	concat(TYPE, _next)
#define list_next_safe	concat(TYPE, _next_safe)
#define list_const_last concat(TYPE, _const_last)
#define list_last	concat(TYPE, _last)
#define list_const_prev	concat(TYPE, _const_prev)
#define list_prev	concat(TYPE, _prev)
#define list_prev_safe	concat(TYPE, _prev_safe)
#define list_count	concat(TYPE, _count)
#define list_add	concat(TYPE, _add)
#define list_add_head	concat(TYPE, _add_head)
#define list_add_tail	concat(TYPE, _add_tail)
#define list_add_after	concat(TYPE, _add_after)
#define list_find	concat(TYPE, _find)
#define list_find_lt	concat(TYPE, _find_lt)
#define list_find_gteq	concat(TYPE, _find_gteq)
#define list_member	concat(TYPE, _member)
#define list_anywhere	concat(TYPE, _anywhere)
#define list_del	concat(TYPE, _del)
#define list_pop	concat(TYPE, _pop)
#define list_swap_all	concat(TYPE, _swap_all)

#define ts_hash_head	concat(ts_hash_head_, TYPE)

#ifndef REALTYPE
#define REALTYPE TYPE
#endif

PREDECL(REALTYPE, list);
struct item {
	uint64_t val;
	struct list_item itm;
	int scratchpad;
};

#if IS_SORTED(REALTYPE)
static int list_cmp(const struct item *a, const struct item *b);

#if IS_HASH(REALTYPE)
static uint32_t list_hash(const struct item *a);
DECLARE(REALTYPE, list, struct item, itm, list_cmp, list_hash);

static uint32_t list_hash(const struct item *a)
{
#ifdef SHITTY_HASH
	/* crappy hash to get some hash collisions */
	return (a->val & 0xFF) ^ (a->val << 29) ^ 0x55AA0000U;
#else
	return jhash_1word(a->val, 0xdeadbeef);
#endif
}

#else
DECLARE(REALTYPE, list, struct item, itm, list_cmp);
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
DECLARE(REALTYPE, list, struct item, itm);
#endif

#define NITEM 10000
#define NITEM_SWAP 100 /* other container for swap */
struct item itm[NITEM], itmswap[NITEM_SWAP];
static struct list_head head = concat(INIT_, REALTYPE)(head);

static void ts_hash_head(struct list_head *h, const char *text,
			 const char *expect)
{
	int64_t us = monotime_since(&ref, NULL);
	SHA256_CTX ctx;
	struct item *item;
	unsigned i = 0;
	uint8_t hash[32];
	char hashtext[65];
	uint32_t swap_count, count;

	count = list_count(h);
	swap_count = htonl(count);

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, &swap_count, sizeof(swap_count));

	frr_each (list, h, item) {
		struct {
			uint32_t val_upper, val_lower, index;
		} hashitem = {
			htonl(item->val >> 32),
			htonl(item->val & 0xFFFFFFFFULL),
			htonl(i),
		};
		SHA256_Update(&ctx, &hashitem, sizeof(hashitem));
		i++;
		assert(i <= count);
	}
	SHA256_Final(hash, &ctx);

	for (i = 0; i < sizeof(hash); i++)
		sprintf(hashtext + i * 2, "%02x", hash[i]);

	printfrr("%7"PRId64"us  %-25s %s%s\n", us, text,
	       expect ? " " : "*", hashtext);
	if (expect && strcmp(expect, hashtext)) {
		printfrr("%-21s %s\n", "EXPECTED:", expect);
		assert(0);
	}
	monotime(&ref);
}
/* hashes will have different item ordering */
#if IS_HASH(REALTYPE) || IS_HEAP(REALTYPE)
#define ts_hash(pos, csum) ts_hash_head(&head, pos, NULL)
#define ts_hashx(pos, csum) ts_hash_head(&head, pos, NULL)
#define ts_hash_headx(head, pos, csum) ts_hash_head(head, pos, NULL)
#else
#define ts_hash(pos, csum) ts_hash_head(&head, pos, csum)
#define ts_hashx(pos, csum) ts_hash_head(&head, pos, csum)
#define ts_hash_headx(head, pos, csum) ts_hash_head(head, pos, csum)
#endif

static void concat(test_, TYPE)(void)
{
	size_t i, j, k, l;
	struct prng *prng;
	struct prng *prng_swap __attribute__((unused));
	struct item *item, *prev __attribute__((unused));
	struct item dummy __attribute__((unused));

	memset(itm, 0, sizeof(itm));
	for (i = 0; i < NITEM; i++)
		itm[i].val = i;

	memset(itmswap, 0, sizeof(itmswap));
	for (i = 0; i < NITEM_SWAP; i++)
		itmswap[i].val = i;

	printfrr("%s start\n", str(TYPE));
	ts_start();

	list_init(&head);
	assert(list_first(&head) == NULL);
#if IS_REVERSE(REALTYPE)
	assert(list_last(&head) == NULL);
#endif

	ts_hash("init", "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119");

#if !IS_ATOMIC(REALTYPE)
	assert(!list_member(&head, &itm[0]));
	assert(!list_member(&head, &itm[1]));
#endif

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

#if !IS_ATOMIC(REALTYPE)
	struct list_head other;

	list_init(&other);
	list_swap_all(&head, &other);

	assert(list_count(&head) == 0);
	assert(!list_first(&head));
	assert(list_count(&other) == k);
	assert(list_first(&other) != NULL);
#if IS_REVERSE(REALTYPE)
	assert(!list_last(&head));
	assert(list_last(&other) != NULL);
#endif
	ts_hash_headx(
		&other, "swap1",
		"a538546a6e6ab0484e925940aa8dd02fd934408bbaed8cb66a0721841584d838");

	prng_swap = prng_new(0x1234dead);
	l = 0;
	for (i = 0; i < NITEM_SWAP; i++) {
		j = prng_rand(prng_swap) % NITEM_SWAP;
		if (itmswap[j].scratchpad == 0) {
			list_add(&head, &itmswap[j]);
			itmswap[j].scratchpad = 1;
			l++;
		}
#if !IS_HEAP(REALTYPE)
		else {
			struct item *rv = list_add(&head, &itmswap[j]);
			assert(rv == &itmswap[j]);
		}
#endif
	}
	assert(list_count(&head) == l);
	assert(list_first(&head) != NULL);
	ts_hash_headx(
		&head, "swap-fill",
		"26df437174051cf305d1bbb62d779ee450ca764167a1e7a94be1aece420008e6");

	list_swap_all(&head, &other);

	assert(list_count(&other) == l);
	assert(list_first(&other));
	ts_hash_headx(
		&other, "swap2a",
		"26df437174051cf305d1bbb62d779ee450ca764167a1e7a94be1aece420008e6");
	assert(list_count(&head) == k);
	assert(list_first(&head) != NULL);
	ts_hash_headx(
		&head, "swap2b",
		"a538546a6e6ab0484e925940aa8dd02fd934408bbaed8cb66a0721841584d838");

	while (list_pop(&other))
		;
	list_fini(&other);
	prng_free(prng_swap);

	ts_ref("swap-cleanup");
#endif /* !IS_ATOMIC */

	k = 0;

#if IS_ATOMIC(REALTYPE)
	struct list_head *chead = &head;
	struct item *citem, *cprev = NULL;

	frr_each(list, chead, citem) {
#else
	const struct list_head *chead = &head;
	const struct item *citem, *cprev = NULL;

	frr_each(list_const, chead, citem) {
#endif

#if IS_HASH(REALTYPE) || IS_HEAP(REALTYPE)
		/* hash table doesn't give sorting */
		(void)cprev;
#else
		assert(!cprev || cprev->val < citem->val);
#if IS_REVERSE(REALTYPE)
		assert(list_const_prev(chead, citem) == cprev);
#endif
#endif
		cprev = citem;
		k++;
	}
	assert(list_count(chead) == k);
#if IS_REVERSE(REALTYPE)
	assert(cprev == list_const_last(chead));
#endif
	ts_ref("walk");

#if IS_REVERSE(REALTYPE) && !IS_HASH(REALTYPE) && !IS_HEAP(REALTYPE)
	cprev = NULL;
	k = 0;

	frr_rev_each(list_const, chead, citem) {
		assert(!cprev || cprev->val > citem->val);
		assert(list_const_next(chead, citem) == cprev);

		cprev = citem;
		k++;
	}
	assert(list_count(chead) == k);
	assert(cprev == list_const_first(chead));

	ts_ref("reverse-walk");
#endif

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
	l = k / 4;
	for (i = 0; i < l; i++) {
		item = list_pop(&head);
		if (prev)
			assert(prev->val < item->val);
		item->scratchpad = 0;
		k--;
		prev = item;
	}
	ts_hash("pop#1", NULL);

	for (i = 0; i < NITEM; i++)
		assertf(list_member(&head, &itm[i]) == itm[i].scratchpad,
			"%zu should:%d is:%d", i, itm[i].scratchpad,
			list_member(&head, &itm[i]));
	ts_hash("member", NULL);

	l = k / 2;
	for (; i < l; i++) {
		item = list_pop(&head);
		if (prev)
			assert(prev->val < item->val);
		item->scratchpad = 0;
		k--;
		prev = item;
	}
	ts_hash("pop#2", NULL);

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

#if !IS_ATOMIC(REALTYPE)
	for (i = 0; i < NITEM; i++)
		assertf(list_member(&head, &itm[i]) == itm[i].scratchpad,
			"%zu should:%d is:%d", i, itm[i].scratchpad,
			list_member(&head, &itm[i]));
	ts_hashx("member", "cb2e5d80f08a803ef7b56c15e981b681adcea214bebc2f55e12e0bfb242b07ca");
#endif

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
#if IS_REVERSE(REALTYPE)
	assert(list_last(&head) != NULL);
#endif
	ts_hash("fill / add_tail", "eabfcf1413936daaf20965abced95762f45110a6619b84aac7d38481bce4ea19");

#if !IS_ATOMIC(REALTYPE)
	struct list_head other;

	list_init(&other);
	list_swap_all(&head, &other);

	assert(list_count(&head) == 0);
	assert(!list_first(&head));
	assert(list_count(&other) == k);
	assert(list_first(&other) != NULL);
#if IS_REVERSE(REALTYPE)
	assert(!list_last(&head));
	assert(list_last(&other) != NULL);
#endif
	ts_hash_head(
		&other, "swap1",
		"eabfcf1413936daaf20965abced95762f45110a6619b84aac7d38481bce4ea19");

	prng_swap = prng_new(0x1234dead);
	l = 0;
	for (i = 0; i < NITEM_SWAP; i++) {
		j = prng_rand(prng_swap) % NITEM_SWAP;
		if (itmswap[j].scratchpad == 0) {
			list_add_tail(&head, &itmswap[j]);
			itmswap[j].scratchpad = 1;
			l++;
		}
	}
	assert(list_count(&head) == l);
	assert(list_first(&head) != NULL);
	ts_hash_head(
		&head, "swap-fill",
		"833e6ae437e322dfbd36eda8cfc33a61109be735b43f15d256c05e52d1b01909");

	list_swap_all(&head, &other);

	assert(list_count(&other) == l);
	assert(list_first(&other));
	ts_hash_head(
		&other, "swap2a",
		"833e6ae437e322dfbd36eda8cfc33a61109be735b43f15d256c05e52d1b01909");
	assert(list_count(&head) == k);
	assert(list_first(&head) != NULL);
	ts_hash_head(
		&head, "swap2b",
		"eabfcf1413936daaf20965abced95762f45110a6619b84aac7d38481bce4ea19");

	while (list_pop(&other))
		;
	list_fini(&other);
	prng_free(prng_swap);

	ts_ref("swap-cleanup");
#endif

	for (i = 0; i < NITEM / 2; i++) {
		j = prng_rand(prng) % NITEM;
		if (itm[j].scratchpad == 1) {
			assert(list_del(&head, &itm[j]) != NULL);
			itm[j].scratchpad = 0;
			k--;
		}
	}
	ts_hash("del-prng", "86d568a95eb429dab3162976c5a5f3f75aabc835932cd682aa280b6923549564");

#if !IS_ATOMIC(REALTYPE)
	for (i = 0; i < NITEM; i++) {
		assertf(list_member(&head, &itm[i]) == itm[i].scratchpad,
			"%zu should:%d is:%d", i, itm[i].scratchpad,
			list_member(&head, &itm[i]));
		assertf(list_anywhere(&itm[i]) == itm[i].scratchpad,
			"%zu should:%d is:%d", i, itm[i].scratchpad,
			list_anywhere(&itm[i]));
	}
	ts_hash("member", "86d568a95eb429dab3162976c5a5f3f75aabc835932cd682aa280b6923549564");
#endif

	l = 0;
	while (l < (k / 4) && (prev = list_pop(&head))) {
		assert(prev->scratchpad != 0);

		prev->scratchpad = 0;
		l++;
	}
	ts_hash("pop#1", "42b8950c880535b2d2e0c980f9845f7841ecf675c0fb9801aec4170d2036349d");

#if !IS_ATOMIC(REALTYPE)
	for (i = 0; i < NITEM; i++) {
		assertf(list_member(&head, &itm[i]) == itm[i].scratchpad,
			"%zu should:%d is:%d", i, itm[i].scratchpad,
			list_member(&head, &itm[i]));
		assertf(list_anywhere(&itm[i]) == itm[i].scratchpad,
			"%zu should:%d is:%d", i, itm[i].scratchpad,
			list_anywhere(&itm[i]));
	}
	ts_hash("member", "42b8950c880535b2d2e0c980f9845f7841ecf675c0fb9801aec4170d2036349d");
#endif
#if IS_REVERSE(REALTYPE)
	i = 0;
	prev = NULL;

	frr_rev_each (list, &head, item) {
		assert(item->scratchpad != 0);
		assert(list_next(&head, item) == prev);

		i++;
		prev = item;
	}
	assert(list_first(&head) == prev);
	assert(list_count(&head) == i);
	ts_hash("reverse-walk", "42b8950c880535b2d2e0c980f9845f7841ecf675c0fb9801aec4170d2036349d");
#endif

	while ((item = list_pop(&head))) {
		assert(item->scratchpad != 0);

		item->scratchpad = 0;
		l++;
	}
	assert(l == k);
	assert(list_count(&head) == 0);
	assert(list_first(&head) == NULL);
	ts_hash("pop#2", "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119");

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
	prng_free(prng);
	printfrr("%s end\n", str(TYPE));
}

#undef ts_hash
#undef ts_hashx
#undef ts_hash_head
#undef ts_hash_headx

#undef item
#undef itm
#undef itmswap
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
#undef list_const_first
#undef list_const_next
#undef list_last
#undef list_prev
#undef list_prev_safe
#undef list_const_last
#undef list_const_prev
#undef list_count
#undef list_add
#undef list_add_head
#undef list_add_tail
#undef list_add_after
#undef list_find
#undef list_find_lt
#undef list_find_gteq
#undef list_member
#undef list_anywhere
#undef list_del
#undef list_pop
#undef list_swap_all

#undef REALTYPE
#undef TYPE
