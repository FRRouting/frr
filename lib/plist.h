// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Prefix list functions.
 * Copyright (C) 1999 Kunihiro Ishiguro
 */

#ifndef _QUAGGA_PLIST_H
#define _QUAGGA_PLIST_H

#include <zebra.h>

#include "stream.h"
#include "vty.h"

#ifdef __cplusplus
extern "C" {
#endif

enum prefix_list_type {
	PREFIX_DENY,
	PREFIX_PERMIT,
};

struct prefix_list;
struct prefix_list_entry;

struct orf_prefix {
	uint32_t seq;
	uint8_t ge;
	uint8_t le;
	struct prefix p;
};

/* Prototypes. */
extern void prefix_list_init(void);
extern void prefix_list_reset(void);
extern void prefix_list_add_hook(void (*func)(struct prefix_list *plst));
extern void prefix_list_delete_hook(void (*func)(struct prefix_list *plist));

extern const char *prefix_list_name(struct prefix_list *plist);
extern afi_t prefix_list_afi(struct prefix_list *plist);
extern struct prefix_list *prefix_list_lookup(afi_t afi, const char *name);

/*
 * prefix_list_apply_which_prefix
 *
 * Allow calling function to learn which prefix
 * caused the DENY or PERMIT.
 *
 * If no pointer is sent in, do not return anything.
 * If it is a empty plist return a NULL pointer.
 *
 * address_mode = the "prefix" being passed in is really an address, match
 * regardless of prefix length (i.e. ge/le are ignored.)  prefix->prefixlen
 * must be /32.
 */
extern enum prefix_list_type
prefix_list_apply_ext(struct prefix_list *plist,
		      const struct prefix_list_entry **matches,
		      union prefixconstptr prefix,
		      bool address_mode);
#define prefix_list_apply(A, B) \
	prefix_list_apply_ext((A), NULL, (B), false)

extern struct prefix_list *prefix_bgp_orf_lookup(afi_t afi, const char *name);
extern struct stream *prefix_bgp_orf_entry(struct stream *s, struct prefix_list *plist,
					   uint8_t init_flag, uint8_t permit_flag,
					   uint8_t deny_flag);
extern int prefix_bgp_orf_set(char *name, afi_t afi, struct orf_prefix *orfp, int permit, int set);
extern void prefix_bgp_orf_remove_all(afi_t afi, char *name);
extern int prefix_bgp_show_prefix_list(struct vty *vty, afi_t afi, char *name,
				       bool use_json);

extern struct prefix_list *prefix_list_get(afi_t afi, int orf,
					   const char *name);
extern void prefix_list_delete(struct prefix_list *plist);
extern int64_t prefix_new_seq_get(struct prefix_list *plist);

extern struct prefix_list_entry *prefix_list_entry_new(void);
extern void prefix_list_entry_delete(struct prefix_list *plist,
				     struct prefix_list_entry *pentry,
				     int update_list);
extern struct prefix_list_entry *
prefix_list_entry_lookup(struct prefix_list *plist, struct prefix *prefix,
			 enum prefix_list_type type, int64_t seq, int le,
			 int ge);

#ifdef __cplusplus
}
#endif

#endif /* _QUAGGA_PLIST_H */
