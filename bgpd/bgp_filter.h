// SPDX-License-Identifier: GPL-2.0-or-later
/* AS path filter list.
 * Copyright (C) 1999 Kunihiro Ishiguro
 */

#ifndef _QUAGGA_BGP_FILTER_H
#define _QUAGGA_BGP_FILTER_H

#define ASPATH_SEQ_NUMBER_AUTO -1

enum as_filter_type { AS_FILTER_DENY, AS_FILTER_PERMIT };


/* Element of AS path filter. */
struct as_filter {
	struct as_filter *next;
	struct as_filter *prev;

	enum as_filter_type type;

	regex_t *reg;
	char *reg_str;

	/* Sequence number. */
	int64_t seq;
};

struct aspath_exclude_list {
	struct aspath_exclude_list *next;
	struct aspath_exclude *bp_as_excl;
};

/* AS path filter list. */
struct as_list {
	char *name;

	struct as_list *next;
	struct as_list *prev;

	struct as_filter *head;
	struct as_filter *tail;
	struct aspath_exclude_list *exclude_list;
};


extern void bgp_filter_init(void);
extern void bgp_filter_reset(void);

extern enum as_filter_type as_list_apply(struct as_list *, void *);

extern struct as_list *as_list_lookup(const char *);
extern void as_list_add_hook(void (*func)(char *));
extern void as_list_delete_hook(void (*func)(const char *));
extern bool config_bgp_aspath_validate(const char *regstr);

#endif /* _QUAGGA_BGP_FILTER_H */
