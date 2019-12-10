/* Linux kernel style list handling function
 *
 * Written from scratch by Timo Teräs <timo.teras@iki.fi>, but modeled
 * after the linux kernel code.
 *
 * This file is free software: you may copy, redistribute and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef LIST_H
#define LIST_H

#ifndef NULL
#define NULL 0L
#endif

#ifndef offsetof
#ifdef __compiler_offsetof
#define offsetof(TYPE,MEMBER) __compiler_offsetof(TYPE,MEMBER)
#else
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif
#endif

#ifndef container_of
#define container_of(ptr, type, member)                                        \
	({                                                                     \
		const typeof(((type *)0)->member) *__mptr = (ptr);             \
		(type *)((char *)__mptr - offsetof(type, member));             \
	})
#endif

struct hlist_head {
	struct hlist_node *first;
};

struct hlist_node {
	struct hlist_node *next;
	struct hlist_node **pprev;
};

static inline int hlist_empty(const struct hlist_head *h)
{
	return !h->first;
}

static inline int hlist_hashed(const struct hlist_node *n)
{
	return n->pprev != NULL;
}

static inline void hlist_del(struct hlist_node *n)
{
	struct hlist_node *next = n->next;
	struct hlist_node **pprev = n->pprev;

	*pprev = next;
	if (next)
		next->pprev = pprev;

	n->next = NULL;
	n->pprev = NULL;
}

static inline void hlist_add_head(struct hlist_node *n, struct hlist_head *h)
{
	struct hlist_node *first = h->first;

	n->next = first;
	if (first)
		first->pprev = &n->next;
	n->pprev = &h->first;
	h->first = n;
}

static inline void hlist_add_after(struct hlist_node *n,
				   struct hlist_node *prev)
{
	n->next = prev->next;
	n->pprev = &prev->next;
	prev->next = n;
}

static inline struct hlist_node **hlist_tail_ptr(struct hlist_head *h)
{
	struct hlist_node *n = h->first;
	if (n == NULL)
		return &h->first;
	while (n->next != NULL)
		n = n->next;
	return &n->next;
}

#define hlist_entry(ptr, type, member) container_of(ptr,type,member)

#define hlist_for_each(pos, head)                                              \
	for (pos = (head)->first; pos; pos = pos->next)

#define hlist_for_each_safe(pos, n, head)                                      \
	for (pos = (head)->first; pos && ({                                    \
					  n = pos->next;                       \
					  1;                                   \
				  });                                          \
	     pos = n)

#define hlist_for_each_entry(tpos, pos, head, member)                          \
	for (pos = (head)->first;                                              \
	     pos && ({                                                         \
		     tpos = hlist_entry(pos, typeof(*tpos), member);           \
		     1;                                                        \
	     });                                                               \
	     pos = pos->next)

#define hlist_for_each_entry_safe(tpos, pos, n, head, member)                  \
	for (pos = (head)->first;                                              \
	     pos && ({                                                         \
		     n = pos->next;                                            \
		     1;                                                        \
	     })                                                                \
	     && ({                                                             \
			tpos = hlist_entry(pos, typeof(*tpos), member);        \
			1;                                                     \
		});                                                            \
	     pos = n)


struct list_head {
	struct list_head *next, *prev;
};

#define LIST_INITIALIZER(l) { .next = &l, .prev = &l }

static inline void list_init(struct list_head *list)
{
	list->next = list;
	list->prev = list;
}

static inline void __list_add(struct list_head *new, struct list_head *prev,
			      struct list_head *next)
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

static inline void list_add(struct list_head *new, struct list_head *head)
{
	__list_add(new, head, head->next);
}

static inline void list_add_tail(struct list_head *new, struct list_head *head)
{
	__list_add(new, head->prev, head);
}

static inline void __list_del(struct list_head *prev, struct list_head *next)
{
	next->prev = prev;
	prev->next = next;
}

static inline void list_del(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
	entry->next = NULL;
	entry->prev = NULL;
}

static inline int list_hashed(const struct list_head *n)
{
	return n->next != n && n->next != NULL;
}

static inline int list_empty(const struct list_head *n)
{
	return !list_hashed(n);
}

#define list_next(ptr, type, member)                                           \
	(list_hashed(ptr) ? container_of((ptr)->next, type, member) : NULL)

#define list_entry(ptr, type, member) container_of(ptr,type,member)

#define list_for_each(pos, head)                                               \
	for (pos = (head)->next; pos != (head); pos = pos->next)

#define list_for_each_safe(pos, n, head)                                       \
	for (pos = (head)->next, n = pos->next; pos != (head);                 \
	     pos = n, n = pos->next)

#define list_for_each_entry(pos, head, member)                                 \
	for (pos = list_entry((head)->next, typeof(*pos), member);             \
	     &pos->member != (head);                                           \
	     pos = list_entry(pos->member.next, typeof(*pos), member))

#define list_for_each_entry_safe(pos, n, head, member)                         \
	for (pos = list_entry((head)->next, typeof(*pos), member),             \
	    n = list_entry(pos->member.next, typeof(*pos), member);            \
	     &pos->member != (head);                                           \
	     pos = n, n = list_entry(n->member.next, typeof(*n), member))

#endif
