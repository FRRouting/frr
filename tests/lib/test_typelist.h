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
#define list_find	concat(TYPE, _find)
#define list_find_lt	concat(TYPE, _find_lt)
#define list_find_gteq	concat(TYPE, _find_gteq)
#define list_del	concat(TYPE, _del)
#define list_pop	concat(TYPE, _pop)

PREDECL(TYPE, list)
struct item {
	uint64_t val;
	struct list_item itm;
	int scratchpad;
};

static int list_cmp(const struct item *a, const struct item *b);

#if IS_HASH(TYPE)
static uint32_t list_hash(const struct item *a);
DECLARE(TYPE, list, struct item, itm, list_cmp, list_hash)

static uint32_t list_hash(const struct item *a)
{
	/* crappy hash to get some hash collisions */
	return a->val ^ (a->val << 29) ^ 0x55AA0000U;
}

#else
DECLARE(TYPE, list, struct item, itm, list_cmp)
#endif

static int list_cmp(const struct item *a, const struct item *b)
{
	if (a->val > b->val)
		return 1;
	if (a->val < b->val)
		return -1;
	return 0;
}

#define NITEM 10000
struct item itm[NITEM];
static struct list_head head = concat(INIT_, TYPE)(head);

static void concat(test_, TYPE)(void)
{
	size_t i, j, k, l;
	struct prng *prng;
	struct item *item, *prev;
	struct item dummy;

	memset(itm, 0, sizeof(itm));
	for (i = 0; i < NITEM; i++)
		itm[i].val = i;

	printf("%s start\n", str(TYPE));
	ts_start();

	list_init(&head);
	ts_ref("init");

	assert(list_first(&head) == NULL);

	prng = prng_new(0);
	k = 0;
	for (i = 0; i < NITEM; i++) {
		j = prng_rand(prng) % NITEM;
		if (itm[j].scratchpad == 0) {
			list_add(&head, &itm[j]);
			itm[j].scratchpad = 1;
			k++;
		} else
			assert(list_add(&head, &itm[j]) == &itm[j]);
	}
	assert(list_count(&head) == k);
	assert(list_first(&head) != NULL);
	ts_ref("fill");

	k = 0;
	prev = NULL;
	for_each(list, &head, item) {
#if IS_HASH(TYPE)
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

#if IS_UNIQ(TYPE)
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
			list_del(&head, &dummy);
		}
	}
	ts_ref("add-dup");
#else /* !IS_UNIQ(TYPE) */
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
		list_del(&head, &dummy);
	}
	ts_ref("add-dup+find_{lt,gteq}");
#endif
#if !IS_HASH(TYPE)
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
			list_del(&head, &itm[j]);
			itm[j].scratchpad = 0;
			l++;
		}
	}
	assert(l + list_count(&head) == k);
	ts_ref("del");

	for_each_safe(list, &head, item) {
		assert(item->scratchpad != 0);

		if (item->val & 1) {
			list_del(&head, item);
			item->scratchpad = 0;
			l++;
		}
	}
	assert(l + list_count(&head) == k);
	ts_ref("for_each_safe+del");

	while ((item = list_pop(&head))) {
		assert(item->scratchpad != 0);

		item->scratchpad = 0;
		l++;
	}
	assert(l == k);
	assert(list_count(&head) == 0);
	assert(list_first(&head) == NULL);
	ts_ref("pop");

	list_fini(&head);
	ts_ref("fini");
	ts_end();
	printf("%s end\n", str(TYPE));
}

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
#undef list_find
#undef list_find_lt
#undef list_find_gteq
#undef list_del
#undef list_pop

#undef TYPE
