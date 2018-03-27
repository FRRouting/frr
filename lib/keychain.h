/* key-chain for authentication.
 * Copyright (C) 2000 Kunihiro Ishiguro
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

#ifndef _ZEBRA_KEYCHAIN_H
#define _ZEBRA_KEYCHAIN_H

#include "qobj.h"

struct keychain {
	char *name;

	struct list *key;

	QOBJ_FIELDS
};
DECLARE_QOBJ_TYPE(keychain)

struct key_range {
	time_t start;
	time_t end;

	uint8_t duration;
};

struct key {
	uint32_t index;

	char *string;

	struct key_range send;
	struct key_range accept;

	QOBJ_FIELDS
};
DECLARE_QOBJ_TYPE(key)

extern void keychain_init(void);
extern struct keychain *keychain_lookup(const char *);
extern struct key *key_lookup_for_accept(const struct keychain *, uint32_t);
extern struct key *key_match_for_accept(const struct keychain *, const char *);
extern struct key *key_lookup_for_send(const struct keychain *);

#endif /* _ZEBRA_KEYCHAIN_H */
