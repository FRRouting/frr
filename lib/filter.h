/*
 * Route filtering function.
 * Copyright (C) 1998 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2, or (at your
 * option) any later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _ZEBRA_FILTER_H
#define _ZEBRA_FILTER_H

#include "if.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum ACL name length */
#define ACL_NAMSIZ                128

/* Filter direction.  */
#define FILTER_IN                 0
#define FILTER_OUT                1
#define FILTER_MAX                2

/* Filter type is made by `permit', `deny' and `dynamic'. */
enum filter_type { FILTER_DENY, FILTER_PERMIT, FILTER_DYNAMIC };

enum access_type { ACCESS_TYPE_STRING, ACCESS_TYPE_NUMBER };

/* Access list */
struct access_list {
	char *name;
	char *remark;

	struct access_master *master;

	enum access_type type;

	struct access_list *next;
	struct access_list *prev;

	struct filter *head;
	struct filter *tail;
};

/* Prototypes for access-list. */
extern void access_list_init(void);
extern void access_list_reset(void);
extern void access_list_add_hook(void (*func)(struct access_list *));
extern void access_list_delete_hook(void (*func)(struct access_list *));
extern struct access_list *access_list_lookup(afi_t, const char *);
extern enum filter_type access_list_apply(struct access_list *access,
					  const void *object);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_FILTER_H */
