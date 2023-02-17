// SPDX-License-Identifier: GPL-2.0-or-later
/* AS path filter list.
 * Copyright (C) 1999 Kunihiro Ishiguro
 */

#ifndef _QUAGGA_BGP_FILTER_H
#define _QUAGGA_BGP_FILTER_H

#define ASPATH_SEQ_NUMBER_AUTO -1

enum as_filter_type { AS_FILTER_DENY, AS_FILTER_PERMIT };

extern void bgp_filter_init(void);
extern void bgp_filter_reset(void);

extern enum as_filter_type as_list_apply(struct as_list *, void *);

extern struct as_list *as_list_lookup(const char *);
extern void as_list_add_hook(void (*func)(char *));
extern void as_list_delete_hook(void (*func)(const char *));
extern bool config_bgp_aspath_validate(const char *regstr);

#endif /* _QUAGGA_BGP_FILTER_H */
